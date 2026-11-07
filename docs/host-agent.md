# Managed host agent

2026-11-07: first implementation validated locally; not deployed. Supported:
Linux amd64/systemd, one fixed v2node.service. One management panel can control a
service containing nodes from multiple business panels.

The panel and node implementation contracts live in FMPanel/docs. This document
describes local installation and recovery, not a second API specification.

## Release artifacts

The fixed source is the public FacMata/v2node repository. A stable release has:

- v2node-linux-amd64 (raw executable; no geo-data replacement)
- manifest.json
- manifest.json.sig (base64 detached Ed25519 signature over exact manifest bytes)

Generate a new signing keypair with `agent signing-keygen --private-key-file ...
--public-key-file ...`. Existing files are not overwritten and the private key
is never printed. The private file is owner-only and contains the base64
64-byte Ed25519 key expected by the signing tool.

`agent sign-release` creates a manifest/signature but does not publish.
The manual managed-release workflow targets main, uses Go 1.27.3 and the
managed-release environment secret MANAGED_RELEASE_SIGNING_KEY. The panel and
agent receive only the public key. Creating the real release environment/key
and publishing assets are separate production-release actions.

## Prepare and enroll (authorized maintenance only)

1. Apply the three managed-host migrations in FMPanel. Configure the public key
   and enable MANAGED_HOST_ENABLED; keep MANAGED_HOST_UPGRADE_ENABLED disabled
   until the first host has been accepted.
2. On the selected Linux host, inspect its actual service, custom drop-ins,
   config, geo-data paths and budget directories. A service-wide restart affects
   every node in that process, including other business panels.
3. Run the verified bridge binary's `agent prepare` with --binary, --manifest,
   --signature and --public-key-file. Defaults: state directory
   /var/lib/v2node-agent, release layout /usr/local/lib/v2node-managed, shared
   directory /var/lib/v2node-managed, config /etc/v2node/config.json.
4. Prepare preserves the existing business unit and writes a managed ExecStart
   drop-in. It backs up existing unit definitions, creates the independent agent
   unit, and does not daemon-reload, enable or restart either service.
   Existing working directory/settings remain in the base unit; standard
   geo assets stay in /usr/local/v2node. An explicit asset location in the base
   unit is preserved. Review effective custom drop-ins before activation.
5. In the admin UI, create a one-use ten-minute registration code. Through the
   maintenance channel, put panel_url, host_id, enrollment_code,
   allowed_api_hosts, server_config and managed_directory in an owner-only JSON
   enrollment file. The prepared managed_directory must match installation.json.
   Only explicitly approved management-panel HTTPS origins go in allowed_api_hosts.
6. Run `agent enroll --enrollment-file /secure/path/enrollment.json`.
   It writes the host identity under the private state directory and the
   independently scoped report-identity.json under managed_directory. Remove
   the used enrollment file via the same maintenance channel.
7. Only after explicit activation approval: reload systemd, enable the two units,
   restart v2node and start v2node-agent. Check actual process/hash, complete
   readiness, independent business confirmation, both panels' nodes and traffic.
   Enable upgrades only after this acceptance.

Without installation.json, `agent run` remains a read-only reporter with no
operation capability. `--once` sends one observation. Normal run polls every
30 seconds and maintains reporting during an authorized operation.

Re-enrollment never silently overwrites an existing identity. A lost enrollment
response requires a new administrator code and explicit preservation/replacement
of the old local identity directory. Do not copy credentials into chat or command
arguments.

## Upgrade and recovery

- current and previous refer to business versions; agent-current remains stable.
- Verify manifest/key, platform, state schema, minimum agent and executable
  digest before switching. Download only fixed fork release assets.
- A shared maintenance lock and operation journal freeze runtime configuration
  during a binary change. Interrupted work is reconciled before new work.
- A fixed Restart=no maintenance drop-in prevents systemd from independently
  spending the recovery budget. Success restores normal restart policy;
  rollback_failed remains stopped for maintenance.
- Authorized starts/restarts reset the service's failed/start-limit counters
  within the journal-owned operation budget, so a preceding manual restart does
  not accidentally prevent recovery.
- Readiness uses actual MainPID/executable bytes, a fresh service boot, expected
  version, completed node/user startup and a 60-second stable window following
  the bounded startup phase. systemd active alone is insufficient.
- A failed candidate restores the recorded original executable and frozen
  configuration. Recovery is bounded; interrupted recovery resumes the same
  journal. Panel network loss does not justify rolling back a healthy process.
- Config, certificate versions, telemetry queue and traffic/budget storage stay
  in place. Never restore an old ledger snapshot with an old binary.
- Existing cold-start user APIs must be reachable, including external panels.
  Initial pre-managed unit rollback is only safe before managed configuration is
  enabled. Afterwards use a compatible managed release/current snapshot.

## AnyTLS configuration

A node opts in through ConfigToken and optional ConfigDirectory. Its original
ApiKey continues to serve business users/traffic. The node creates a local
baseline before the panel can apply a revision; no baseline is reconstructed
from a desired revision after local state loss.

Only the target inbound is replaced; limiter/budget storage and other inbounds
remain. Versioned certificate files, local TLS leaf checks and applied/published
separation prevent a failed candidate from becoming a subscription version.
Configuration history can be copied into a new draft for recovery.

Core-wide routes/DNS/outbound/protocol changes are not part of the initial
AnyTLS capability and are rejected explicitly. Existing non-budget traffic
reporting semantics are unchanged; no claim is made that every last in-memory
legacy statistics batch is lossless across a maintenance restart.

## Verification

Go unit checks, real systemd startup/upgrade/recovery, interrupted-agent and
machine-reboot recovery, AnyTLS inbound replacement and occupied-port recovery
were exercised in an isolated Debian amd64 machine. A real pinned Xray/AnyTLS
client verified authenticated payload forwarding and rejection of a wrong pin.
That does not replace acceptance of each customer's actual URI importer or
Mihomo/mobile version. Keep legacy publication until those clients are verified.

See tests/managed-host for disposable-environment acceptance fixtures and the
workspace release-readiness record for exact scope and remaining production gates.
