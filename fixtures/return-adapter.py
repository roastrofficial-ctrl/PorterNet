"""Opaque Host fixture. Only local LG is available; no carriage keys or route."""
import hashlib,json,os,subprocess,sys
from pathlib import Path
root,app=map(Path,sys.argv[1:3]);app.mkdir(parents=True,exist_ok=True)
(app/'started').write_text('independent Host attention\n')
contract='PORTER-HOST-ADAPTER/1'
print(json.dumps({'contract':contract,'runtime_observation':'ADAPTER_READY'}),flush=True)
for line in sys.stdin:
    offer=json.loads(line);cl=offer['collection'];p=cl['package']
    (app/'observation.json').write_text(json.dumps(cl))
    returned={**p,'package':'PKG-'+hashlib.sha256(p['package'].encode()).hexdigest()[:32],
              'from':p['to'],'to':p['from'],'payload':{'opaque':'return'},'in_reply_to':p['package']}
    (app/'return.json').write_text(json.dumps(returned))
    command=['native_fixture','lodge',str(root),json.dumps(returned)]
    if len(sys.argv)>3: command+=['after-lg']
    result=subprocess.run(command,capture_output=True,text=True)
    if result.returncode: os._exit(23)
    print(json.dumps({'contract':contract,'dispatch':offer['dispatch'],
                     'runtime_observation':'ADAPTER_RETURNED_CONTROL'}),flush=True)
