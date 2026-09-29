import base64
import json
import subprocess
import tempfile
from pathlib import Path

from porter.native import open_frame, public_key, seal
from porter.introduction import proof, verify_proof
from porter.lodgement import lodge
from porter.protocol import package


def run(*arguments):
    return subprocess.check_output(
        ["/usr/local/bin/native_fixture", *arguments], text=True
    ).strip()


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
print("Python ↔ Rust protected native carriage: PASS")

# D-006: preserve the actual Python Package/proof representation. Do not
# translate admission to Rust's private format to make this journey succeed.
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    value = package("sender", "recipient", "opaque.demo", {"opaque": "lab"})
    lodge(root / "python", value)
    facts = list((root / "python/lodgements/lodged").glob("LG-*.json"))
    assert len(facts) == 1
    assert json.loads(facts[0].read_text())["package"] == value
    admission = proof("fixture-secret", value)
    assert verify_proof("fixture-secret", value, admission)
    carried = {"package": value, "admission": admission}
    frame = seal(carried, "sender", sender_private, "recipient",
                 recipient_public, "PACKAGE", "CU-package-boundary")
    encoded = base64.b64encode(frame).decode()
    assert json.loads(run("open", "recipient", recipient_private,
                          "sender", sender_public, encoded)) == carried
    received = subprocess.run(
        ["/usr/local/bin/native_fixture", "receive", "recipient",
         recipient_private, "sender", sender_public, encoded, str(root / "rust")],
        text=True, capture_output=True, check=False,
    )
    assert received.returncode != 0, "D-006 changed: reassess the boundary"
    assert "NativeFrameRefused" in received.stderr, received.stderr
    assert not list((root / "rust/acceptances").glob("*.json"))
    assert not list((root / "rust/collections").glob("*.json"))
    print("D-006 reproduced: Python LG -> protected Rust decode -> pre-AC refusal")
    print("Lifecycle: BLOCKED; AC absent; CL absent; Host not started")
