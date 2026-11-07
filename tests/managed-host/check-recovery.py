import pathlib,json,subprocess,time,uuid,hashlib,ssl,socket
ROOT=pathlib.Path('/work')
def run(*a):subprocess.run(a,check=True,stdout=subprocess.DEVNULL)
def read(path):
    try:return json.loads(pathlib.Path(path).read_text())
    except FileNotFoundError:return None
def wait(test,label,timeout=240):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        result=test()
        if result:return result
        time.sleep(.5)
    raise RuntimeError(label+' timed out')
version='v1.4.0'
run('/work/'+version,'agent','sign-release','--binary','/work/'+version,'--key-file','/work/test.key','--manifest','/work/'+version+'.json','--release-version',version,'--commit','a'*40,'--min-agent-version','v1.0.0','--sequence','4')
agent=pathlib.Path('/usr/local/lib/v2node-managed/agent-current');temporary=agent.with_name('agent-current.test');temporary.symlink_to('/work/'+version);temporary.replace(agent)
run('systemctl','start','v2node-agent.service')
wait(lambda:(read(ROOT/'heartbeat.json') or {}).get('agent_version')==version,'new agent',45)
def submit(tamper=False):
    heartbeat=read(ROOT/'heartbeat.json');raw=(ROOT/(version+'.json')).read_text();sig=(ROOT/(version+'.json.sig')).read_text()
    if tamper:sig='A'*88
    op={'id':str(uuid.uuid4()),'action':'upgrade','expires_at':int(time.time())+900,'params':{'release_id':str(uuid.uuid4()),'from_sha256':heartbeat['service_sha256'],'config_sha256':heartbeat['config_sha256'],'topology_digest':'e'*64},'release':{'id':str(uuid.uuid4()),'manifest':raw,'signature':sig,'manifest_sha256':hashlib.sha256(raw.encode()).hexdigest()}}
    tmp=ROOT/'control.tmp';tmp.write_text(json.dumps(op));tmp.replace(ROOT/'control.json');return op['id']
def result(id):
    value=read(ROOT/'result.json');return value if value and value['operation_id']==id else None
id=submit(True);r=wait(lambda:result(id),'bad signature');assert r['status']=='failed' and r['result']['code']=='SIGNATURE_INVALID',r
assert read('/var/lib/v2node-managed/ready.json')['service_version']=='v1.3.0'
print('PASS: invalid signature rejected before switching',flush=True)
id=submit();wait(lambda:(read('/var/lib/v2node-managed/operation.json') or {}).get('phase')=='switched','switch journal')
run('systemctl','kill','--kill-whom=main','--signal=KILL','v2node-agent.service')
r=wait(lambda:result(id),'agent restart recovery');assert r['status']=='rolled_back',r
assert read('/var/lib/v2node-managed/ready.json')['service_version']=='v1.3.0'
assert read('/var/lib/v2node/config/test/current.json')['current_revision']==101
assert pathlib.Path('/var/lib/v2node/traffic/test/preserve.txt').read_text()=='budget-state-must-not-be-replaced'
for port in [14443,14444]:
    with socket.create_connection(('127.0.0.1',port),timeout=5) as sock:
        with ssl._create_unverified_context().wrap_socket(sock,server_hostname='localhost') as tls:assert tls.getpeercert(binary_form=True)
print('PASS: killed agent recovered from durable journal; managed config and both TLS listeners survived rollback',flush=True)
