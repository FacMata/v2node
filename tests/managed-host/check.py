import pathlib,subprocess,json,time,uuid,hashlib,ssl,socket,sys
ROOT=pathlib.Path('/work')
def run(*args):subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
def wait(test,label,timeout=260):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if test():return
        time.sleep(1)
    raise RuntimeError(label+' timed out')
def read(path):
    try:return json.loads(pathlib.Path(path).read_text())
    except FileNotFoundError:return None
def setup():
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout','/work/local.key','-out','/work/local.crt','-days','1','-subj','/CN=local managed-host test','-addext','subjectAltName=DNS:panel.test,DNS:github.com,IP:127.0.0.1')
    pathlib.Path('/usr/local/share/ca-certificates/managed-host-test.crt').write_bytes((ROOT/'local.crt').read_bytes());run('update-ca-certificates')
    with open('/etc/hosts','a') as f:f.write('\n127.0.0.1 panel.test github.com\n')
    run('systemd-run','--unit=managed-host-test-panel','/usr/bin/python3','/work/mock.py')
    wait(lambda: subprocess.run(['curl','-sSf','https://panel.test:8443/'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0,'test panel',20)
    pathlib.Path('/etc/v2node').mkdir(exist_ok=True)
    pathlib.Path('/etc/v2node/config.json').write_text(json.dumps({'Log':{'Level':'warn'},'Nodes':[{'ApiHost':'https://panel.test:8443','NodeID':1,'ApiKey':'synthetic','TrafficBudgetDirectory':'/var/lib/v2node/traffic/test','Telemetry':{'Enabled':False}}]}))
    for version in ['v1.0.0','v1.1.0','v1.2.0']:
        run('/work/v1.0.0','agent','sign-release','--binary','/work/'+version,'--key-file','/work/test.key','--manifest','/work/'+version+'.json','--release-version',version,'--commit','a'*40,'--min-agent-version','v1.0.0','--sequence',str(['v1.0.0','v1.1.0','v1.2.0'].index(version)+1))
    run('/work/v1.0.0','agent','prepare','--binary','/work/v1.0.0','--manifest','/work/v1.0.0.json','--signature','/work/v1.0.0.json.sig','--public-key-file','/work/test.pub')
    enrollment={'panel_url':'https://panel.test:8443','host_id':str(uuid.uuid4()),'enrollment_code':'c'*64,'allowed_api_hosts':['https://panel.test:8443'],'server_config':'/etc/v2node/config.json','managed_directory':'/var/lib/v2node-managed'}
    file=ROOT/'enrollment.json';file.write_text(json.dumps(enrollment));file.chmod(0o600)
    run('/work/v1.0.0','agent','enroll','--enrollment-file',str(file));file.unlink()
    run('systemctl','daemon-reload');run('systemctl','start','v2node.service')
    wait(lambda:read('/var/lib/v2node-managed/ready.json'),'initial readiness',30)
    pathlib.Path('/var/lib/v2node/traffic/test/preserve.txt').write_text('budget-state-must-not-be-replaced')
    run('systemctl','start','v2node-agent.service')
    wait(lambda:read(ROOT/'heartbeat.json'),'initial heartbeat',30)
def submit(version):
    heartbeat=read(ROOT/'heartbeat.json');raw=(ROOT/(version+'.json')).read_text();sig=(ROOT/(version+'.json.sig')).read_text()
    op={'id':str(uuid.uuid4()),'action':'upgrade','expires_at':int(time.time())+900,'params':{'release_id':str(uuid.uuid4()),'from_sha256':heartbeat['service_sha256'],'config_sha256':heartbeat['config_sha256'],'topology_digest':'e'*64},'release':{'id':str(uuid.uuid4()),'manifest':raw,'signature':sig,'manifest_sha256':hashlib.sha256(raw.encode()).hexdigest()}}
    (ROOT/'control.json').write_text(json.dumps(op));return op['id']
def done(id):
    r=read(ROOT/'result.json');return r if r and r['operation_id']==id else None
def handshake():
    context=ssl._create_unverified_context()
    with socket.create_connection(('127.0.0.1',14443),timeout=5) as s:
        with context.wrap_socket(s,server_hostname='localhost') as tls:assert tls.getpeercert(binary_form=True)
if len(sys.argv)>1 and sys.argv[1]=='setup':setup();print('READY: real systemd, AnyTLS listener and management heartbeat',flush=True)
elif sys.argv[1]=='success':
    id=submit('v1.1.0');wait(lambda:done(id),'upgrade',220);r=done(id);assert r['status']=='succeeded',r['result'];assert read('/var/lib/v2node-managed/ready.json')['service_version']=='v1.1.0';handshake();print('PASS: signed download, atomic switch, new process readiness and AnyTLS handshake',flush=True)
elif sys.argv[1]=='failure':
    wait(lambda:read(ROOT/'heartbeat.json')['service_version']=='v1.1.0','post-upgrade report',45)
    id=submit('v1.2.0');wait(lambda:done(id),'failed candidate recovery',300);r=done(id);assert r['status']=='rolled_back',r['result'];assert read('/var/lib/v2node-managed/ready.json')['service_version']=='v1.1.0';assert pathlib.Path('/var/lib/v2node/traffic/test/preserve.txt').read_text()=='budget-state-must-not-be-replaced';handshake();print('PASS: startup failure recovered old process, retained state directory and serving TLS',flush=True)
