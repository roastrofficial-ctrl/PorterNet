"""Fixed gates precede this fresh-store, process-separated lifecycle experiment."""
import base64,json,subprocess,tempfile,time
from pathlib import Path
from porter.canonical import canonical
from porter.carriage import package_digest
from porter.native import public_key
from porter.protocol import package

private=base64.b64encode(bytes([7])*32).decode(); peer_private=base64.b64encode(bytes([11])*32).decode()
public=public_key(private);peer_public=public_key(peer_private);key=b'fixture-secret'.hex()
def call(command,fail=False):
    p=subprocess.run(command,capture_output=True,text=True)
    assert (p.returncode!=0) if fail else (p.returncode==0), (command[0:2],p.stdout,p.stderr)
    if fail: assert 'Interrupted' in p.stderr or p.returncode==23, p.stderr
    return p.stdout.strip()
def rust(*a,fail=False):return call(['native_fixture',*map(str,a)],fail)
def py(root,op,*a,fail=False):return call(['python','/roundtrip-worker.py',op,str(root),*map(str,a)],fail)
def facts(root):
    result={}
    for folder in ['lodgements','acceptances','collections']:
        result[folder]=[json.loads(p.read_text()) for p in (root/folder).rglob('*.json') if '/locks/' not in str(p) and json.loads(p.read_text()).get('kind') in {'LODGEMENT','REMOTE_ACCEPTANCE','COLLECTION'}]
    return result

def journey(faults):
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);origin=root/'python';dest=root/'rust';app=root/'rust-app';return_app=root/'python-app'
        snapshots=[]
        def snapshot(name,responsibility,knowledge,reconstruction,unknown):
            item={'checkpoint':name,'canonical_facts':{'python':facts(origin),'rust':facts(dest)},
                  'recoverable_responsibility':responsibility,'participant_knowledge':{
                      'statement':knowledge,
                      'python_retained':{str(p.relative_to(origin)):json.loads(p.read_text())
                          for folder in ['carriage','receipts','native/evidence']
                          for p in (origin/folder).rglob('*.json')},
                      'rust_retained':{str(p.relative_to(dest)):json.loads(p.read_text())
                          for folder in ['native_spool/observations','native_spool/evidence']
                          for p in (dest/folder).rglob('*.json')}},
                  'reconstruction':reconstruction,'unknown':unknown}
            snapshots.append(item)
        def silence(store,application,leg):
            start=time.monotonic();samples=0
            while time.monotonic()-start<0.3:
                assert not facts(store)['collections'];assert not application.exists()
                samples+=1;time.sleep(0.05)
            print(json.dumps({'silence_leg':leg,'elapsed_seconds':time.monotonic()-start,'samples':samples,'CL':False,'adapter_started':False}),flush=True)
        p=package('sender','recipient','opaque.demo',{'opaque':'é','number':1.0},ttl=3600)
        p['future_field']={'unchanged':[None,'𐀀']}
        intro={'protocol':'PORTER-INTRODUCTION/1','kind':'INTRODUCTION','introduction':'IN-fixture',
               'sender':'sender','recipient':'recipient','issuer':'fixture','established_at_ms':1,
               'terms':{'kinds':['opaque.demo'],'maximum_package_bytes':4096,'maximum_outstanding_count':8,
                        'maximum_outstanding_bytes':32768,'expires_at_ms':9000}}
        rust('establish',dest,json.dumps(intro),key)
        py(origin,'lodge',json.dumps(p),*(['after-lg'] if faults else []),fail=faults)
        assert len(facts(origin)['lodgements'])==1
        if faults:snapshot('after origin LG','Python origin Porter','Origin knows LG; recipient knows nothing','Outgoing Package from LG','Remote AC and application action')
        frame=py(origin,'frame','PACKAGE')
        assert json.loads((origin/'carriage'/f"{p['package']}.json").read_text())['knowledge']=='ACCEPTANCE_UNKNOWN'
        if faults:
            snapshot('after protected carriage attempt','Python origin Porter','Origin has an attempt; no receipt','Retry exact Package from LG','Whether a remote AC occurred')
            frame=py(origin,'frame','PACKAGE')
        receive=['receive','recipient',peer_private,'sender',public,frame,dest]
        rust(*receive,*(['after-ac'] if faults else []),fail=faults)
        ac_path=dest/'acceptances'/f"{p['package']}.json";ac_bytes=ac_path.read_bytes();ac=json.loads(ac_bytes)
        assert canonical(ac['package'])==canonical(p) and ac['package_digest']==package_digest(p)
        assert not facts(dest)['collections'] and not app.exists()
        if faults:snapshot('after recipient AC','Rust recipient Porter','Rust knows AC; Python acceptance unknown','AC reconstructs inbox and receipt','Host action and origin evidence retention')
        rust(*receive);assert ac_path.read_bytes()==ac_bytes
        receipt=rust('outgoing',dest,'recipient',peer_private,'sender',public,'ACCEPTANCE_EVIDENCE')
        if faults:snapshot('before origin retains AC evidence','Rust recipient Porter','Recipient AC; origin acceptance unknown','Exact replay regenerates original receipt','Origin has not retained evidence')
        py(origin,'receive',receipt)
        assert (origin/'receipts'/f"{p['package']}.json").exists()
        assert json.loads((origin/'carriage'/f"{p['package']}.json").read_text())['knowledge']=='REMOTE_ACCEPTANCE_KNOWN'
        silence(dest,app,'outbound')
        if faults:snapshot('after recipient AC before attention','Rust recipient Porter','Both Porters know AC; Host has no CL','Candidate from AC','Future attention and application meaning')
        attention=['host_attention',str(dest),p['package']]
        if faults:
            call(attention+['--crash-after-cl'],True)
            assert len(facts(dest)['collections'])==1 and not app.exists()
            snapshot('after recipient CL before adapter offer','Rust local Host custody','CL is durable; no adapter offer','Same CL can be offered after restart','Application action')
        adapter=['python','/return-adapter.py',str(dest),str(app)]
        if faults:
            # Host process fails because the adapter dies after the Return LG threshold.
            result=subprocess.run(attention+adapter+['after-lg'],capture_output=True,text=True)
            assert result.returncode!=0 and 'adapter control' in result.stderr
            assert len(facts(dest)['lodgements'])==1
            snapshot('after Return LG','Rust origin Porter for Return; Rust Host for original','Rust knows Return LG; Python knows no Return AC','Return Package from LG; original CL remains','Remote Return acceptance and processing')
        call(attention+adapter)
        observed=json.loads((app/'observation.json').read_text())
        assert canonical(observed['package'])==canonical(p) and observed['acceptance']==ac['acceptance']
        returned=json.loads((app/'return.json').read_text())
        assert returned['in_reply_to']==p['package'] and len(facts(dest)['lodgements'])==1
        return_lg=facts(dest)['lodgements'][0]
        assert canonical(return_lg['package'])==canonical(returned)
        assert return_lg['package_digest']==package_digest(returned)
        returned=return_lg['package']
        rust('queue',dest,'recipient',peer_private,'sender',public,json.dumps(returned),key)
        back=rust('outgoing',dest,'recipient',peer_private,'sender',public,'PACKAGE')
        py(origin,'receive',back,*(['after-ac'] if faults else []),fail=faults)
        return_path=origin/'acceptances'/f"{returned['package']}.json";return_bytes=return_path.read_bytes();return_ac=json.loads(return_bytes)
        assert canonical(return_ac['package'])==canonical(returned) and return_ac['package_digest']==package_digest(returned)
        if faults:snapshot('after Return AC','Python recipient Porter for Return','Python knows Return AC; Rust has no returned AC evidence','AC reconstructs inbox and receipt on restart','Python Host action and Rust evidence retention')
        py(origin,'receive',back);assert return_path.read_bytes()==return_bytes
        silence(origin,return_app,'return')
        # AC evidence is its own protected journey, independent of Host attention.
        back_receipt=py(origin,'frame','ACCEPTANCE_EVIDENCE')
        assert rust('receive','recipient',peer_private,'sender',public,back_receipt,dest)=='EvidenceRetained'
        retained=[json.loads(p.read_text()) for p in (dest/'native_spool/evidence').glob('*.json')]
        assert len(retained)==1 and retained[0]['value']['acceptance']==return_ac['acceptance']
        assert retained[0]['value']['package_digest']==package_digest(returned)
        py(origin,'attention',return_app)
        observation=json.loads((return_app/'observation.json').read_text())['observed_collection']
        assert canonical(observation['package'])==canonical(returned) and observation['acceptance']==return_ac['acceptance']
        assert len(facts(origin)['collections'])==1 and len(facts(dest)['collections'])==1
        assert ac_path.read_bytes()==ac_bytes and return_path.read_bytes()==return_bytes
        print(('Interrupted' if faults else 'Happy')+' round trip: Python LG -> Rust AC -> silence -> independent CL -> Return LG -> Python AC -> silence -> independent CL PASS',flush=True)
        if faults:
            assert len(snapshots)==8
            print('INTERRUPTION_FACTS='+json.dumps(snapshots,ensure_ascii=False),flush=True)
journey(False)
journey(True)
