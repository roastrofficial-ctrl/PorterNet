"""Independent Python consumption of the frozen normative bytes; no AC calls."""
import copy
import hashlib
import hmac
import json
import sys

from porter.introduction import canonical, proof, verify_proof


def verify_vectors(path):
    with open(path) as stream:
        vector = json.load(stream)
    package = vector['package']
    key = bytes.fromhex(vector['capability_hex'])
    encoded = canonical(package)
    assert encoded == vector['canonical_package_utf8'].encode('utf-8')
    assert encoded.hex() == vector['canonical_package_hex']
    digest = hashlib.sha256(encoded).digest()
    assert digest.hex() == vector['sha256_hex']
    assert 'sha256:' + digest.hex() == vector['digest_text']
    message = digest.hex().encode('ascii')
    assert message.hex() == vector['hmac_input_hex']
    assert vector['hmac_algorithm'] == 'HMAC-SHA256'
    assert hmac.digest(key, message, 'sha256').hex() == vector['proof_hex']
    assert proof(key.decode('utf-8'), package) == vector['admission']
    assert verify_proof(key.decode('utf-8'), package, vector['admission'])
    for negative in vector['negative']:
        assert len(negative['change']) == 1
        case = copy.deepcopy(vector)
        case.update(negative['change'])
        if 'counterexample_hmac_input_hex' in negative:
            wrong_message = bytes.fromhex(negative['counterexample_hmac_input_hex'])
            assert 'hmac-sha256:' + hmac.digest(key, wrong_message, 'sha256').hex() == case['admission']['proof']
        accepted = verify_proof(bytes.fromhex(case['capability_hex']).decode('utf-8'),
                                case['package'], case['admission'])
        assert accepted is negative['expected'], negative['name']
    print(f"Python possession: 1 positive + {len(vector['negative'])} negative vectors PASS", flush=True)


if __name__ == '__main__':
    verify_vectors(sys.argv[1])
