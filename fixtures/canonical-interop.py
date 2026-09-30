"""Extend custody evidence only after both canonical and possession gates pass."""
import base64
import json
import os
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from porter.canonical import canonical, loads
from porter.carriage import package_digest
from porter.daemon import Porter
from porter.introduction import proof, verify_proof
from porter.lodgement import lodge
from porter.native import NativeFrameRefused, open_frame, public_key, seal


def run(*args):
    return subprocess.check_output(['/usr/local/bin/native_fixture', *args], text=True).strip()


def experiment():
    suite = json.loads(Path('/spec/vectors/canonical-json-1.json').read_text())
    secret = bytes.fromhex(suite['capability_hex']).decode('utf-8')
    sender_private = base64.b64encode(bytes([7])*32).decode()
    recipient_private = base64.b64encode(bytes([11])*32).decode()
    sender_public, recipient_public = public_key(sender_private), public_key(recipient_private)
    introduction = {
        'protocol':'PORTER-INTRODUCTION/1', 'kind':'INTRODUCTION', 'introduction':'IN-fixture',
        'sender':'sender', 'recipient':'recipient', 'issuer':'local-fixture-authority',
        'established_at_ms':1,
        'terms':{'kinds':['opaque.demo'], 'maximum_package_bytes':4096,
                 'maximum_outstanding_count':4, 'maximum_outstanding_bytes':16384,
                 'expires_at_ms':9000},
    }
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for case in suite['positive']:
            local = root / case['name']
            package = loads(case['package_input_utf8'])
            admission = proof(secret, package)
            assert admission == case['admission']
            lodge(local / 'origin', package)
            carried = {'package':package, 'admission':admission}
            frame = seal(carried, 'sender', sender_private, 'recipient', recipient_public, 'PACKAGE', 'CU-canonical')
            rust = local / 'rust'
            run('establish', str(rust), json.dumps(introduction), suite['capability_hex'])
            assert run('receive','recipient',recipient_private,'sender',sender_public,
                       base64.b64encode(frame).decode(),str(rust)) == 'PackageAccepted'
            ac_path = rust / 'acceptances' / (package['package']+'.json')
            ac_bytes = ac_path.read_bytes()
            ac = loads(ac_bytes)
            assert ac['package_digest'] == package_digest(package) == case['package_digest'], case['name']
            assert canonical(ac['package']).hex() == case['package_canonical_hex']
            assert not list((rust / 'collections').glob('*.json'))
            app = local / 'application'
            assert not app.exists()
            # Restart the receiver and recover the exact same AC.
            assert run('receive','recipient',recipient_private,'sender',sender_public,
                       base64.b64encode(frame).decode(),str(rust)) == 'PackageAccepted'
            assert ac_path.read_bytes() == ac_bytes
            # Reverse protected encoding, then the real Python admission path.
            reverse_frame = base64.b64decode(run('seal','sender',sender_private,'recipient',
                recipient_public,'PACKAGE','CU-reverse',json.dumps(carried)))
            _, opened = open_frame(reverse_frame[9:],'recipient',recipient_private,{'sender':sender_public})
            assert canonical(opened['package']).hex() == case['package_canonical_hex']
            assert verify_proof(secret,opened['package'],opened['admission'])
            python_root = local / 'python-recipient'
            py = Porter('recipient',python_root,{},relationships={'sender':{
                'secret':secret,'kinds':['opaque.demo'],'max_package_bytes':4096,
                'max_outstanding_packages':4,'max_outstanding_bytes':16384,
                'expires_at':int(time.time())+3600}},require_introductions=True)
            receipt = py.deposit(opened['package'],admission=opened['admission'])
            assert receipt['package_digest'] == case['package_digest']
            assert py.deposit(opened['package'],admission=opened['admission']) == receipt
            assert not list((python_root / 'collections').glob('CL-*.json'))
            # Host lifecycle is separate from every receive operation above.
            subprocess.check_output(['/usr/local/bin/host_attention',str(rust),package['package'],
                                     'python','/opaque-adapter.py',str(app)],text=True)
            observed = json.loads((app / 'observation.json').read_text())['observed_collection']
            assert observed['acceptance'] == ac['acceptance']
            assert canonical(observed['package']).hex() == case['package_canonical_hex']
            assert ac_path.read_bytes() == ac_bytes
        print(f"Canonical journeys: {len(suite['positive'])} Python LG -> Rust AC/replay -> independent CL/adapter PASS",flush=True)
        print(f"Reverse protected frames: {len(suite['positive'])} Python possession/AC/replay digests agree PASS",flush=True)

        # Construct authenticated hostile plaintext directly. Production sealers
        # correctly cannot emit these values; this is an adversarial fixture.
        metadata = {'protocol':'PORTER-CARRIAGE/1','version':1,'unit':'CU-hostile',
                    'class':'PACKAGE','from':'sender','to':'recipient'}
        aad = canonical(metadata)
        shared = X25519PrivateKey.from_private_bytes(bytes([7])*32).exchange(
            X25519PublicKey.from_public_bytes(base64.b64decode(recipient_public)))
        key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,
                   info=b'PORTER-CARRIAGE/1\0'+aad).derive(shared)

        def hostile(raw):
            nonce = os.urandom(12)
            envelope = {**metadata,'nonce':base64.b64encode(nonce).decode(),
                        'ciphertext':base64.b64encode(AESGCM(key).encrypt(nonce,raw,aad)).decode()}
            body = canonical(envelope)
            return struct.pack('!4sBI',b'PRTR',1,len(body))+body

        attacks = [(case['name'],hostile(bytes.fromhex(case['input_hex']))) for case in suite['negative']]
        valid = hostile(b'{}')
        # Same decoded unit twice; authentication would still match after a
        # last-key-wins parse. Strict native envelope parsing must reject it.
        duplicate = valid[9:-1]+b',"unit":"CU-hostile"}'
        attacks.append(('duplicate-envelope-name',struct.pack('!4sBI',b'PRTR',1,len(duplicate))+duplicate))
        for name, frame in attacks:
            try:
                open_frame(frame[9:],'recipient',recipient_private,{'sender':sender_public})
            except NativeFrameRefused:
                pass
            else:
                raise AssertionError('Python accepted '+name)
            encoded = base64.b64encode(frame).decode()
            decoded = subprocess.run(['/usr/local/bin/native_fixture','open','recipient',recipient_private,
                                      'sender',sender_public,encoded],capture_output=True,text=True)
            assert decoded.returncode != 0 and 'NativeFrameRefused' in decoded.stderr, name
            destination = root / ('invalid-'+name)
            received = subprocess.run(['/usr/local/bin/native_fixture','receive','recipient',recipient_private,
                                      'sender',sender_public,encoded,str(destination)],capture_output=True,text=True)
            assert received.returncode != 0 and 'NativeFrameRefused' in received.stderr, name
            assert not list((destination / 'acceptances').glob('*.json'))
            assert not list((destination / 'collections').glob('*.json'))
        print(f"Authenticated hostile JSON: {len(attacks)} rejected by both native decoders; Rust AC/CL absent PASS",flush=True)

        # A complete, valid Package must never be silently projected into the
        # Rust model. Unknown fields must survive AC unchanged (D-003).
        extended = {**loads(suite['positive'][0]['package_input_utf8']), 'reply_to':'sender'}
        extended_proof = proof(secret,extended)
        assert verify_proof(secret,extended,extended_proof)
        frame = seal({'package':extended,'admission':extended_proof},'sender',sender_private,
                     'recipient',recipient_public,'PACKAGE','CU-schema-boundary')
        encoded = base64.b64encode(frame).decode()
        assert loads(run('open','recipient',recipient_private,'sender',sender_public,encoded))['package'] == extended
        destination = root / 'schema-boundary'
        run('establish',str(destination),json.dumps(introduction),suite['capability_hex'])
        received = subprocess.run(['/usr/local/bin/native_fixture','receive','recipient',recipient_private,
                                  'sender',sender_public,encoded,str(destination)],capture_output=True,text=True)
        assert received.returncode == 0, received.stderr
        ac = json.loads(next((destination / 'acceptances').glob('*.json')).read_text())
        assert canonical(ac['package']) == canonical(extended)
        print('Complete Package: extension preserved through production AC PASS',flush=True)


experiment()
