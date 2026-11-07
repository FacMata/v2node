import pathlib,subprocess,base64,stat
ROOT=pathlib.Path('/work');V='v1.6.0'
def run(*a):subprocess.run(a,check=True,stdout=subprocess.DEVNULL)
run('/work/'+V,'agent','signing-keygen','--private-key-file','/work/extra.key','--public-key-file','/work/extra.pub')
assert len(base64.b64decode((ROOT/'extra.key').read_bytes()))==64
assert len(base64.b64decode((ROOT/'extra.pub').read_bytes()))==32
assert (ROOT/'extra.key').stat().st_mode & 0o077 == 0
before=(ROOT/'extra.key').read_bytes()
assert subprocess.run(['/work/'+V,'agent','signing-keygen','--private-key-file','/work/extra.key','--public-key-file','/work/extra.pub'],capture_output=True).returncode!=0
assert (ROOT/'extra.key').read_bytes()==before
run('/work/'+V,'agent','sign-release','--binary','/work/'+V,'--key-file','/work/test.key','--manifest','/work/'+V+'.json','--release-version',V,'--commit','a'*40,'--min-agent-version','v1.0.0','--sequence','6')
unit=pathlib.Path('/etc/systemd/system/v2node.service');original=unit.read_bytes()
custom=original+b'\n[Service]\nWorkingDirectory=/etc/v2node\nEnvironment=TEST_KEEP=1\nEnvironment=XRAY_LOCATION_ASSET=/custom-assets\n'
unit.write_bytes(custom)
run('/work/'+V,'agent','prepare','--state-dir','/var/lib/v2node-agent-prepare-check','--layout','/usr/local/lib/v2node-prepare-check','--managed-dir','/var/lib/v2node-prepare-check','--binary','/work/'+V,'--manifest','/work/'+V+'.json','--signature','/work/'+V+'.json.sig','--public-key-file','/work/test.pub')
assert unit.read_bytes()==custom
dropin=pathlib.Path('/etc/systemd/system/v2node.service.d/50-managed-exec.conf').read_text()
assert 'ExecStart=\nExecStart=/usr/local/lib/v2node-prepare-check/current' in dropin
assert 'XRAY_LOCATION_ASSET' not in dropin
run('systemd-analyze','verify','/etc/systemd/system/v2node.service','/etc/systemd/system/v2node-agent.service')
unit.write_bytes(original)
print('PASS: key generation preserves existing files; prepare preserves custom unit settings and uses valid systemd drop-ins',flush=True)
