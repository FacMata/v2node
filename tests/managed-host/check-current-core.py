import pathlib,json,subprocess,time,uuid,hashlib,socket
ROOT=pathlib.Path('/work');VERSION='v1.5.0'
def run(*a):subprocess.run(a,check=True,stdout=subprocess.DEVNULL)
def read(path):
    try:return json.loads(pathlib.Path(path).read_text())
    except FileNotFoundError:return None
def wait(test,label,timeout=220):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        value=test()
        if value:return value
        time.sleep(.5)
    raise RuntimeError(label+' timed out')
run('systemctl','stop','v2node-agent.service')
agent=pathlib.Path('/usr/local/lib/v2node-managed/agent-current');tmp=agent.with_name('agent-current.test');tmp.symlink_to('/work/'+VERSION);tmp.replace(agent)
run('/work/'+VERSION,'agent','sign-release','--binary','/work/'+VERSION,'--key-file','/work/test.key','--manifest','/work/'+VERSION+'.json','--release-version',VERSION,'--commit','a'*40,'--min-agent-version','v1.0.0','--sequence','5')
run('systemctl','start','v2node-agent.service');wait(lambda:(read(ROOT/'heartbeat.json') or {}).get('agent_version')==VERSION,'current agent',45)
h=read(ROOT/'heartbeat.json');raw=(ROOT/(VERSION+'.json')).read_text();id=str(uuid.uuid4())
op={'id':id,'action':'upgrade','expires_at':int(time.time())+900,'params':{'release_id':str(uuid.uuid4()),'from_sha256':h['service_sha256'],'config_sha256':h['config_sha256'],'topology_digest':'e'*64},'release':{'id':str(uuid.uuid4()),'manifest':raw,'signature':(ROOT/(VERSION+'.json.sig')).read_text(),'manifest_sha256':hashlib.sha256(raw.encode()).hexdigest()}}
tmp=ROOT/'control.tmp';tmp.write_text(json.dumps(op));tmp.replace(ROOT/'control.json')
r=wait(lambda:read(ROOT/'result.json') if (read(ROOT/'result.json') or {}).get('operation_id')==id else None,'current core upgrade')
assert r['status']=='succeeded',r
ready=read('/var/lib/v2node-managed/ready.json');assert ready['service_version']==VERSION
payload=read(ROOT/'config-target.json')['payload'];payload['server_port']=14443
def publish(revision):
    raw=json.dumps(payload,separators=(',',':'));v={'schema_version':1,'mode':'managed','revision':revision,'attempt':1,'credential_generation':1,'scope':'inbound','payload_digest':hashlib.sha256(raw.encode()).hexdigest(),'payload':payload};tmp=ROOT/'config-target.tmp';tmp.write_text(json.dumps(v));tmp.replace(ROOT/'config-target.json')
publish(103);wait(lambda:(read(ROOT/'config-ack.json') or {}).get('revision')==103 and (read(ROOT/'config-ack.json') or {}).get('result')=='applied','current-core configuration',35)
assert read('/var/lib/v2node-managed/ready.json')['pid']==ready['pid']
hash_before=read('/var/lib/v2node-managed/ready.json')['config_sha256']
publish(104);wait(lambda:(read(ROOT/'config-ack.json') or {}).get('revision')==104,'same-runtime revision',35)
assert read('/var/lib/v2node-managed/ready.json')['config_sha256']==hash_before
held=socket.socket();held.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);held.bind(('127.0.0.1',14555));held.listen();payload['server_port']=14555;publish(105)
wait(lambda:(read(ROOT/'config-ack.json') or {}).get('revision')==105 and (read(ROOT/'config-ack.json') or {}).get('result')=='rolled_back','current-core inbound recovery',35);held.close()
assert read('/var/lib/v2node/config/test/current.json')['current_revision']==104
print('PASS: current upstream core + Go 1.27.3 signed upgrade, same-process configuration, publication-only revision and occupied-port recovery',flush=True)
