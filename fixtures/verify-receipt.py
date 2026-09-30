"""Stored receipt schema vectors, verified before any experiment AC."""
import json,subprocess,tempfile
from pathlib import Path
from porter.daemon import Porter
from porter.native import NativeFrameRefused
from porter.lodgement import lodge
v=json.loads(Path('/spec/vectors/acceptance-evidence-1.json').read_text())
with tempfile.TemporaryDirectory() as directory:
    root=Path(directory)
    print(subprocess.check_output(['native_fixture','receipt-vectors','/spec/vectors/acceptance-evidence-1.json',str(root/'rust')],text=True).strip(),flush=True)
    p=Porter('sender',root/'python',{},native_private_key='BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=',native_listen='127.0.0.1:0')
    unit=p.native.queue_package_custodian(v['package'],'recipient',{})
    queued=root/'python/native/outgoing'/f"{unit['unit']}.json"
    cases=[(v['receipt'],True),({**v['receipt'],'future':True},True)]
    cases += [({**v['receipt'],**n['change']},False) for n in v['negative']]
    for receipt,expected in cases:
        try:p.native._validate_custodian_receipt(receipt,queued);accepted=True
        except NativeFrameRefused:accepted=False
        assert accepted==expected,receipt
    print(f"Python receipt: 2 positive + {len(v['negative'])} negative vectors PASS",flush=True)
