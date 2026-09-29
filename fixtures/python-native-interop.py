import base64
import json
import subprocess
import tempfile
import runpy
from pathlib import Path

from porter.native import open_frame, public_key, seal
from porter.introduction import proof, verify_proof
from porter.lodgement import lodge


def run(*arguments):
    return subprocess.check_output(
        ["/usr/local/bin/native_fixture", *arguments], text=True
    ).strip()


# Mandatory gate: both native implementations consume the SAME immutable file.
vector_path = '/spec/vectors/package-possession-1.json'
runpy.run_path('/verify-possession.py')['verify_vectors'](vector_path)
print(run('vectors', vector_path), flush=True)
vector = json.loads(Path(vector_path).read_text())

sender_private = base64.b64encode(bytes([7]) * 32).decode()
recipient_private = base64.b64encode(bytes([11]) * 32).decode()
sender_public = public_key(sender_private)
recipient_public = public_key(recipient_private)
value = {"opaque": {"language": "irrelevant"}}

rust_frame = base64.b64decode(
    run(
        "seal",
        "sender",
        sender_private,
        "recipient",
        recipient_public,
        "PACKAGE",
        "CU-rust-to-python",
        json.dumps(value, separators=(",", ":")),
    )
)
rust_envelope, rust_value = open_frame(
    rust_frame[9:], "recipient", recipient_private, {"sender": sender_public}
)
assert rust_envelope["unit"] == "CU-rust-to-python"
assert rust_value == value

python_frame = seal(
    value,
    "sender",
    sender_private,
    "recipient",
    recipient_public,
    "CEREMONY_RESULT",
    "CU-python-to-rust",
)
opened = json.loads(
    run(
        "open",
        "recipient",
        recipient_private,
        "sender",
        sender_public,
        base64.b64encode(python_frame).decode(),
    )
)
assert opened == value
print("Python ↔ Rust protected frame codec: PASS", flush=True)

# Preserve the original journey's LG / seal / open / receive calls. The fixed
# normative Package replaces random Package construction; no proof translation.
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    value = vector['package']
    lodge(root / "python", value)
    facts = list((root / "python/lodgements/lodged").glob("LG-*.json"))
    assert len(facts) == 1
    assert json.loads(facts[0].read_text())["package"] == value
    admission = proof(bytes.fromhex(vector['capability_hex']).decode('utf-8'), value)
    assert admission == vector['admission']
    assert verify_proof("fixture-secret", value, admission)
    carried = {"package": value, "admission": admission}
    frame = seal(carried, "sender", sender_private, "recipient",
                 recipient_public, "PACKAGE", "CU-package-boundary")
    encoded = base64.b64encode(frame).decode()
    assert json.loads(run("open", "recipient", recipient_private,
                          "sender", sender_public, encoded)) == carried
    introduction = {
        'protocol': 'PORTER-INTRODUCTION/1', 'kind': 'INTRODUCTION',
        'introduction': 'IN-fixture', 'sender': 'sender', 'recipient': 'recipient',
        'issuer': 'local-fixture-authority', 'established_at_ms': 1,
        'terms': {'kinds': ['opaque.demo'], 'maximum_package_bytes': 4096,
                  'maximum_outstanding_count': 4, 'maximum_outstanding_bytes': 16384,
                  'expires_at_ms': 9000},
    }

    def establish(destination):
        run('establish', str(destination), json.dumps(introduction), vector['capability_hex'])

    def receive(destination, encoded_frame=encoded):
        return run('receive', 'recipient', recipient_private, 'sender', sender_public,
                   encoded_frame, str(destination))

    # Admission rejection must remain pre-AC, not just a standalone verifier result.
    for case in vector['negative']:
        destination = root / case['name']
        changed = dict(vector)
        changed.update(case['change'])
        if 'capability_hex' in case['change']:
            # The sender proves possession of the wrong key; recipient retains K.
            bad_admission = proof(bytes.fromhex(changed['capability_hex']).decode('utf-8'), value)
        else:
            bad_admission = changed['admission']
        bad_frame = seal({'package': changed['package'], 'admission': bad_admission},
                         'sender', sender_private, 'recipient', recipient_public,
                         'PACKAGE', 'CU-' + case['name'])
        establish(destination)
        assert receive(destination, base64.b64encode(bad_frame).decode()) == 'PackageRefused'
        assert not list((destination / 'acceptances').glob('*.json'))
        assert not list((destination / 'collections').glob('*.json'))
    print('Rust node: 11 negative possession cases refused before AC', flush=True)

    destination = root / 'rust'
    app = root / 'application'
    establish(destination)  # Independent recipient-local standing, before arrival.
    assert receive(destination) == 'PackageAccepted'
    acceptance_path = destination / 'acceptances' / (value['package'] + '.json')
    original_ac = acceptance_path.read_bytes()
    ac = json.loads(original_ac)
    assert ac['kind'] == 'REMOTE_ACCEPTANCE'
    assert ac['package'] == value and ac['package_digest'] == vector['digest_text']
    assert not list((destination / 'collections').glob('*.json'))
    assert not app.exists()
    # Receiver exits and is restarted; exact replay must recover the same AC.
    assert receive(destination) == 'PackageAccepted'
    assert acceptance_path.read_bytes() == original_ac
    assert not list((destination / 'collections').glob('*.json'))
    assert not app.exists()
    print('Python LG -> protected carriage -> Rust possession -> durable AC: PASS', flush=True)
    print('Before independent attention: CL absent; adapter not started', flush=True)

    # This explicit, later command is the only source of Host attention.
    attention = ['/usr/local/bin/host_attention', str(destination), value['package']]
    cl = json.loads(subprocess.check_output(attention + ['--stop-after-cl'], text=True))
    cl_path = destination / 'collections' / (value['package'] + '.json')
    original_cl = cl_path.read_bytes()
    assert json.loads(original_cl) == cl
    assert cl['package'] == value and cl['acceptance'] == ac['acceptance']
    assert not app.exists()
    print('Independent attention -> durable CL; stop before adapter offer: PASS', flush=True)

    # A dead adapter does not roll back custody or invent application facts.
    died = subprocess.run(attention + ['python', '-c', 'raise SystemExit(7)'],
                          text=True, capture_output=True, check=False)
    assert died.returncode != 0
    assert cl_path.read_bytes() == original_cl
    assert not app.exists()
    print('Adapter death after CL preserves exact custody fact: PASS', flush=True)

    offer_command = attention + ['python', '/opaque-adapter.py', str(app)]
    for _ in range(2):
        returned = json.loads(subprocess.check_output(offer_command, text=True))
        assert returned['runtime_observation'] == 'ADAPTER_RETURNED_CONTROL'
        assert returned['collection'] == cl['collection']
        observation = json.loads((app / 'observation.json').read_text())
        assert observation['observed_collection'] == cl
        assert cl_path.read_bytes() == original_cl
    assert (app / 'started').exists()
    assert acceptance_path.read_bytes() == original_ac
    print('Recovered CL -> frozen adapter opportunity; duplicate opportunity tolerated: PASS', flush=True)
    print('Lifecycle: LG -> AC -> later independent attention -> CL -> adapter opportunity PASS', flush=True)
