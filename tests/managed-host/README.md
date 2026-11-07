# Disposable Linux acceptance fixtures

These scripts are for a disposable Linux amd64/systemd machine only. They write
test units and files under /etc and /var/lib, install a test-only CA, and map
panel.test/github.com to a local mock. They must not run on production or a
shared machine. No production credential or user data is used.

The exercised environment was an isolated OrbStack Debian bookworm amd64 machine
with only /tmp/codex-v2node-check-work mounted as /work. It was deleted after
acceptance. Docker/other user machines were not stopped or altered.

## Inputs

Copy the Python fixtures to /tmp/codex-v2node-check-work. Build test binaries into
that directory using the repository's Go toolchain and GOEXPERIMENT=jsonv2,
GOOS=linux, GOARCH=amd64, CGO_ENABLED=0. Inject cmd.version via the normal ldflags.
The fixtures use v1.0.0, v1.1.0, v1.3.0, v1.4.0, v1.5.0 and v1.6.0 labels;
v1.2.0 is a deliberately failing executable. These are fixture labels, not real
release claims or proof that arbitrary historical binaries are format-compatible.

keygen/main.go creates a test-only Ed25519 keypair in the shared temporary folder.
proxy-check/main.go builds an actual pinned AnyTLS client and verifies a known
payload through SOCKS → AnyTLS → local HTTP origin. Its certificate input comes
from the trusted local fixture material, not arbitrary first-use network discovery.

## Sequence and assertions

1. check.py setup: test TLS panel, signed manifests, prepare/enroll, real systemd
   services and AnyTLS baseline.
2. check.py success / failure: signed upgrade with stable readiness, then bad
   candidate startup and recovery of the original version/state directory.
3. check-config.py: managed config enrollment, leaf replacement without a PID
   change, unaffected second inbound, occupied-port failure and recovery, no
   repeated execution of the same failed attempt.
4. check-recovery.py: bad signature rejected before switch; kill the agent during
   a switched journal and let the stable agent process recover.
5. check-reboot.py prepare, restart only the disposable machine, then
   check-reboot.py verify: reconcile an interrupted transaction on machine boot.
6. check-current-core.py: repeat affected upgrade/configuration paths against the
   merged current fork and toolchain, including a publication-only revision.
7. check-prepare.py: key-file non-overwrite and private mode, preservation of
   custom service settings, valid systemd drop-ins. Run last; it intentionally
   prepares a second test layout.
8. proxy-check <port> <trusted-cert.pem> [wrong]: correct pin forwards the exact
   122880-byte payload; wrong pin is rejected. Check both test inbounds.

Backend HTTP/auth/state tests are in FMPanel/tests/managed-host-smoke.php and
use independent temporary configuration/cache paths plus SQLite. Frontend checks
use an isolated local PHP/SQLite instance and explicit test data, never a
production API fallback.

Remove the temporary machine, binaries, CA/key files, local preview entry points
and test database after use. Preserve these text fixtures and acceptance records.
