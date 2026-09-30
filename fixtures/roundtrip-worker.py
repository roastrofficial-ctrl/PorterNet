"""One Python participant operation per process; no listener or arrival Host hook."""
import base64, json, os, shlex, sys, time
from pathlib import Path
from porter.daemon import Porter
from porter.lodgement import lodge
from porter.native import public_key, open_frame, seal
from porter.host_runtime import Adapter, HostRuntime

command, location, *args = sys.argv[1:]
root = Path(location)
private = base64.b64encode(bytes([7])*32).decode()
peer_public = public_key(base64.b64encode(bytes([11])*32).decode())
secret = 'fixture-secret'
if command == 'lodge':
    try:
        print(json.dumps(lodge(root,json.loads(args[0]),fail_after='lodged' if len(args)>1 else None)))
    except Exception:
        if len(args)>1: os._exit(23)
        raise
    sys.exit()
porter = Porter('sender',root,{},relationships={'recipient':{
    'secret':secret,'kinds':['opaque.demo'],'max_package_bytes':4096,
    'max_outstanding_packages':8,'max_outstanding_bytes':32768,
    'expires_at':4102444800}},require_introductions=True,
    native_private_key=private,native_listen='127.0.0.1:0',
    native_rendezvous={'recipient':{'host':'unused','port':1,'public_key':peer_public}})
if command == 'frame':
    porter.native.stage_host_outgoing()
    units=[json.loads(p.read_text()) for p in (root/'native/outgoing').glob('*.json')]
    unit=next(u for u in units if u['class']==args[0])
    frame=seal(unit['value'],'sender',private,'recipient',peer_public,unit['class'],unit['unit'])
    print(base64.b64encode(frame).decode())
elif command == 'receive':
    envelope,value=open_frame(base64.b64decode(args[0])[9:],'sender',private,{'recipient':peer_public})
    if len(args)>1:
        original=porter.deposit
        def interrupted(*a,**k):
            original(*a,**k)
            os._exit(23)
        porter.deposit=interrupted
    porter.native.receive(envelope,value)
elif command == 'attention':
    adapter=Adapter(shlex.join(['python','/opaque-adapter.py',args[0]]))
    try:
        host=HostRuntime(root,'origin-host',adapter,{'opaque.demo'},1,100,root/'host-journal.jsonl')
        print(host.visit())
    finally:
        adapter.close()
else:
    raise ValueError(command)
