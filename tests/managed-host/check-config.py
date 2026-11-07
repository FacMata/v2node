import pathlib,subprocess,json,time,ssl,socket,hashlib,os,threading
ROOT=pathlib.Path('/work');STATE=pathlib.Path('/var/lib/v2node/config/test/current.json')
def run(*a):subprocess.run(a,check=True,stdout=subprocess.DEVNULL)
def read(path):
    try:return json.loads(pathlib.Path(path).read_text())
    except FileNotFoundError:return None
def wait(test,label,seconds=45):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if test():return
        time.sleep(.5)
    raise RuntimeError(label+' timed out')
def leaf(port):
    with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
        with ssl._create_unverified_context().wrap_socket(s,server_hostname='localhost') as t:return hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest()
run('systemctl','stop','v2node-agent.service','v2node.service')
run('systemctl','restart','managed-host-test-panel.service')
directory=pathlib.Path('/usr/local/lib/v2node-managed/releases/v1.3.0');directory.mkdir(parents=True,exist_ok=True)
target=directory/'v2node';target.write_bytes((ROOT/'v1.3.0').read_bytes());target.chmod(0o755)
for name in ['current','agent-current']:
    path=pathlib.Path('/usr/local/lib/v2node-managed')/name;temporary=path.with_name(name+'.test');temporary.symlink_to(target);temporary.replace(path)
config=read('/etc/v2node/config.json');config['Nodes'][0]['ConfigToken']='d'*64;config['Nodes'][0]['ConfigDirectory']='/var/lib/v2node/config/test'
other=dict(config['Nodes'][0]);other.pop('ConfigToken');other.pop('ConfigDirectory');other['NodeID']=2;other['TrafficBudgetDirectory']='/var/lib/v2node/traffic/test2';config['Nodes'].append(other)
pathlib.Path('/etc/v2node/config.json').write_text(json.dumps(config))
run('systemctl','start','v2node.service');wait(lambda:read(STATE),'baseline');wait(lambda:(read(ROOT/'config-ack.json') or {}).get('result')=='bootstrap_ready','baseline ack')
pid=read('/var/lib/v2node-managed/ready.json')['pid'];other_leaf=leaf(14444)
run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout','/work/candidate.key','-out','/work/candidate.crt','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost')
certificate=(ROOT/'candidate.crt').read_text();key=(ROOT/'candidate.key').read_text()
der=subprocess.check_output(['openssl','x509','-in','/work/candidate.crt','-outform','DER']);expected=hashlib.sha256(der).hexdigest()
payload={'protocol':'anytls','listen_ip':'127.0.0.1','server_port':14443,'network':'tcp','network_settings':{},'tls':1,
    'tls_settings':{'cert_mode':'remote','server_name':'localhost','tls_cert':certificate,'tls_key':key},'routes':[],
    'base_config':{'pull_interval':2,'push_interval':60,'device_online_min_traffic':0,'node_report_min_traffic':0}}
def publish(revision):
    raw=json.dumps(payload,separators=(',',':'))
    envelope={'schema_version':1,'mode':'managed','revision':revision,'attempt':1,'credential_generation':1,'scope':'inbound','payload_digest':hashlib.sha256(raw.encode()).hexdigest(),'payload':payload}
    tmp=ROOT/'config-target.tmp';tmp.write_text(json.dumps(envelope));tmp.replace(ROOT/'config-target.json')
publish(101);wait(lambda:(read(ROOT/'config-ack.json') or {}).get('result')=='applied','certificate swap')
assert read(STATE)['current_revision']==101
assert leaf(14443)==expected
assert leaf(14444)==other_leaf
assert read('/var/lib/v2node-managed/ready.json')['pid']==pid
print('PASS: managed baseline, versioned material, AnyTLS leaf swap, unchanged process and second inbound',flush=True)
held=socket.socket();held.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);held.bind(('127.0.0.1',14555));held.listen()
payload['server_port']=14555;publish(102)
wait(lambda:(read(ROOT/'config-ack.json') or {}).get('revision')==102 and (read(ROOT/'config-ack.json') or {}).get('result')=='rolled_back','inbound rollback')
held.close();assert read(STATE)['current_revision']==101;assert leaf(14443)==expected;assert leaf(14444)==other_leaf
time.sleep(3);assert read(STATE)['current_revision']==101
assert pathlib.Path('/var/lib/v2node/traffic/test/preserve.txt').read_text()=='budget-state-must-not-be-replaced'
print('PASS: occupied-port failure restores old inbound; same failed attempt is not reapplied; state directory retained',flush=True)
