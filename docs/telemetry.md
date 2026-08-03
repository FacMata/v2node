# Connection telemetry

Connection telemetry is enabled by default for every `Nodes` entry. It reuses
the existing Server API identity:

- `node_type=v2node`
- `node_id=<NodeID>`
- `Authorization: Bearer <ApiKey>`

Node identity remains in the query string. The API key is sent only in the
Authorization header so reverse-proxy access logs do not record it. FMPanel
temporarily accepts the legacy `token=<ApiKey>` query during rolling upgrades,
but current v2node releases never emit it.

The sender accepts HTTPS endpoints only, except loopback HTTP in tests. No
telemetry-specific key, signature, nonce, source-sealing key, catalog key, or
environment secret is required.

At startup and config reload, v2node fetches collector control with the same
Server API identity. Telemetry starts only after an authenticated control
response supplies a valid mode, epoch, and TTL. Legacy configurations without
a control endpoint probe the event endpoint instead. Any unsuccessful exchange
skips telemetry for the affected node and emits one warning without affecting
node startup, reload, or proxy forwarding.

When `Telemetry.Endpoint` is omitted, v2node uses:

```text
<ApiHost>/api/v2/server/telemetry/connection-events
```

Optional configuration:

```json
{
  "Nodes": [
    {
      "ApiHost": "https://panel.example.com",
      "NodeID": 123,
      "ApiKey": "existing-v2-config-token",
      "Telemetry": {
        "Enabled": true,
        "Endpoint": "https://panel.example.com/api/v2/server/telemetry/connection-events",
        "ControlEndpoint": "https://panel.example.com/api/v2/server/telemetry/control",
        "QueueDirectory": "/var/lib/v2node/telemetry/123"
      }
    }
  ]
}
```

Missing `Telemetry` configuration means enabled. An unreachable, unsupported,
or unauthenticated endpoint is detected automatically, so it does not require
an explicit `Telemetry.Enabled: false`. The flag remains available only for an
intentional per-node opt-out that must not contact either endpoint.

FMPanel controls collection with three modes:

- `off`: stop collection and delivery; queued records from an older epoch are
  discarded and included in the durable loss count.
- `observe`: collect, publish, project, and score without automatic restriction.
- `auto_protect`: use the same telemetry path and allow FMPanel enforcement when
  its server-side readiness gates pass.

The latest control epoch, absolute TTL expiry, and pending loss count survive a
process restart. A stale or conflicting epoch is rejected. When control expires,
collection and delivery pause until control is refreshed; proxy forwarding is
never stopped.

Each attributable connection attempt is reported as one raw event, including
dispatch, route, and outbound failures. When the terminal outcome cannot be
observed honestly, the event reports `unknown` with
`terminal_outcome_unobservable`; it never invents an accepted outcome. Source
IP and normalized destination address are sent as canonical plaintext inside
the HTTPS JSON request. Runtime listener, local port, SNI or HTTP host when
available, protocol, inbound tag, latency, completeness, and loss reason are
included for schema v2. Events are buffered and uploaded every 5 seconds by
default. v2node does not classify probes or aggregate minute buckets; FMPanel
owns those operations. URL paths, query strings within user traffic, payloads,
DNS message bodies, process names, and application package names are not
collected.

The local bounded queue, retry backoff, durable batch ID, event ID, stream ID,
and sequence behavior remain fail-open for proxy forwarding. Once startup
control succeeds, a later missing route (`404`), rate limit, or server failure
keeps the batch queued and retries while control remains valid. Authentication
failures disable delivery for that batch without affecting proxy forwarding.
Queue eviction, expiry, epoch invalidation, and corrupt-head quarantine are
counted by affected event sequence span and carried into a later batch.

Queue files use owner-only permissions and XChaCha20-Poly1305. The queue key is
derived from the current Server API key, so there is no separately provisioned
secret. Server API key rotation intentionally invalidates old queued batches;
all affected node entries must be reconfigured together.

`pipeline-state-<node>.json` and the queue loss counter contain only control and
counter metadata and use owner-only permissions. They do not contain source IP,
destination, or Server API credentials.

Default bounds:

| Field | Default |
|---|---:|
| `QueueMaxBytes` | 268435456 |
| `QueueMaxAgeSeconds` | 21600 |
| `BufferSize` | 4096 |
| `FlushIntervalSeconds` | 5 |
| `RequestTimeoutSeconds` | 10 |
| `RetryMinSeconds` / `RetryMaxSeconds` | 1 / 60 |
| `ShutdownTimeoutSeconds` | 5 |

Config reload rebuilds telemetry managers and applies endpoint or queue-setting
changes. Telemetry failure never blocks node startup, reload, or forwarding.
