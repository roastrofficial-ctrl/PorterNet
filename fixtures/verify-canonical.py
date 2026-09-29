"""Independent Python checks of fixed canonical bytes and Package digests."""
import hashlib
import json
import sys

from porter.canonical import canonical, loads
from porter.carriage import package_digest
from porter.introduction import proof, verify_proof


def verify_vectors(path):
    suite = json.load(open(path))
    key = bytes.fromhex(suite['capability_hex']).decode('utf-8')
    observed = {}
    for case in suite['positive']:
        value = loads(case['input_utf8'])
        encoded = canonical(value)
        assert encoded.hex() == case['canonical_hex'], case['name']
        assert encoded == case['canonical_utf8'].encode('utf-8'), case['name']
        assert hashlib.sha256(encoded).hexdigest() == case['sha256_hex'], case['name']
        assert canonical(loads(encoded)) == encoded, case['name']
        package = loads(case['package_input_utf8'])
        assert canonical(package).hex() == case['package_canonical_hex'], case['name']
        assert package_digest(package) == case['package_digest'], case['name']
        assert proof(key, package) == case['admission'], case['name']
        assert verify_proof(key, package, case['admission']), case['name']
        observed[case['name']] = encoded
    for case in suite['negative']:
        try:
            loads(bytes.fromhex(case['input_hex']))
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('must reject ' + case['name'])
    for group in suite['equivalent_groups']:
        assert len({observed[name] for name in group}) == 1
    for left, right in suite['distinct_pairs']:
        assert observed[left] != observed[right]
    for value in [float('nan'), [float('inf')], {'bad': '\ud800'}]:
        try:
            canonical(value)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('invalid direct value accepted')
    print(f"Python canonical: {len(suite['positive'])} positive + {len(suite['negative'])} negative vectors; bytes/digests/proofs/idempotence PASS", flush=True)


if __name__ == '__main__':
    verify_vectors(sys.argv[1])
