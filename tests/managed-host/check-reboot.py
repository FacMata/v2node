import pathlib,json,subprocess,time,uuid,hashlib,sys
ROOT=pathlib.Path('/work')
def run(*a):subprocess.run(a,check=True,stdout=subprocess.DEVNULL)
def read(path):
    try:return json.loads(pathlib.Path(path).read_text())
    except FileNotFoundError:return None
def wait(test,label,timeout=260):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        value=test()
        if value:return value
        time.sleep(.5)
    raise RuntimeError(label+' timed out')
if sys.argv[1]=='prepare':
    unit='[Unit]\nDescription=Isolated test panel\nAfter=network.target\nRequiresMountsFor=/work\nBefore=v2node.service v2node-agent.service\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /work/mock.py\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n'
    pathlib.Path('/etc/systemd/system/managed-host-test-panel-boot.service').write_text(unit)
    run('systemctl','stop','managed-host-test-panel.service')
    run('systemctl','daemon-reload');run('systemctl','enable','managed-host-test-panel-boot.service','v2node.service','v2node-agent.service')
    run('systemctl','start','managed-host-test-panel-boot.service')
    agent=pathlib.Path('/usr/local/lib/v2node-managed/agent-current');tmp=agent.with_name('agent-current.test');tmp.symlink_to('/usr/local/lib/v2node-managed/releases/v1.4.0/v2node');tmp.replace(agent)
    h=read(ROOT/'heartbeat.json');raw=(ROOT/'v1.4.0.json').read_text()
    op={'id':str(uuid.uuid4()),'action':'upgrade','expires_at':int(time.time())+900,'params':{'release_id':str(uuid.uuid4()),'from_sha256':h['service_sha256'],'config_sha256':h['config_sha256'],'topology_digest':'e'*64},'release':{'id':str(uuid.uuid4()),'manifest':raw,'signature':(ROOT/'v1.4.0.json.sig').read_text(),'manifest_sha256':hashlib.sha256(raw.encode()).hexdigest()}}
    tmp=ROOT/'control.tmp';tmp.write_text(json.dumps(op));tmp.replace(ROOT/'control.json')
    (ROOT/'reboot-operation.txt').write_text(op['id'])
    wait(lambda:(read('/var/lib/v2node-managed/operation.json') or {}).get('phase')=='switched','pre-reboot switch')
    run('systemctl','kill','--kill-whom=main','--signal=KILL','v2node-agent.service')
    run('systemctl','stop','v2node-agent.service')
    print('READY: interrupted transaction retained for machine reboot',flush=True)
else:
    id=(ROOT/'reboot-operation.txt').read_text()
    r=wait(lambda:(read(ROOT/'result.json') if (read(ROOT/'result.json') or {}).get('operation_id')==id else None),'cold boot recovery')
    assert r['status']=='rolled_back',r
    assert read('/var/lib/v2node-managed/ready.json')['service_version']=='v1.3.0'
    assert read('/var/lib/v2node/config/test/current.json')['current_revision']==101
    print('PASS: machine reboot reconciled interrupted upgrade before new work; original version and managed config restored',flush=True)
