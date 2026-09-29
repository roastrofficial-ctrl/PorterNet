"""Application-owned observation fixture; knows only the local adapter contract."""
import json
import os
import sys
from pathlib import Path

CONTRACT = 'PORTER-HOST-ADAPTER/1'
root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)
(root / 'started').write_text('local adapter entered\n')
print(json.dumps({'contract': CONTRACT, 'runtime_observation': 'ADAPTER_READY'}), flush=True)
for line in sys.stdin:
    offer = json.loads(line)
    assert offer['contract'] == CONTRACT
    collection = offer['collection']
    assert collection['kind'] == 'COLLECTION'
    # Repeated Collection opportunities replace this application's observation.
    # This is application idempotence, not a PORTER processing claim.
    target = root / 'observation.json'
    temporary = root / 'observation.tmp'
    with temporary.open('w') as stream:
        json.dump({'observed_collection': collection, 'dispatch': offer['dispatch']}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)
    directory = os.open(root, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({'contract': CONTRACT, 'dispatch': offer['dispatch'],
                      'runtime_observation': 'ADAPTER_RETURNED_CONTROL'}), flush=True)
