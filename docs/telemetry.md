# Connection telemetry

Connection telemetry is enabled by default for every `Nodes` entry. It reuses
the existing Server API identity:

- `node_type=v2node`
- `node_id=<NodeID>`
- `token=<ApiKey>`

The sender accepts HTTPS endpoints only, except loopback HTTP in tests. No
telemetry-specific key, signature, nonce, source-sealing key, catalog key, or
environment secret is required.

At startup and config reload, v2node probes the endpoint with the same Server
API identity. Telemetry starts only when the authenticated route responds with
the expected invalid-payload code. Any unsuccessful exchange skips telemetry
for the affected node and emits one warning without affecting node startup,
reload, or proxy forwarding.

When `Telemetry.Endpoint` is omitted, v2node uses:

```text
<ApiHost>/api/v2/server/telemetry/connection-buckets
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
        "Endpoint": "https://panel.example.com/api/v2/server/telemetry/connection-buckets",
        "QueueDirectory": "/var/lib/v2node/telemetry/123"
      }
    }
  ]
}
```

Missing `Telemetry` configuration means enabled. An unreachable, unsupported,
or unauthenticated endpoint is detected automatically, so it does not require
an explicit `Telemetry.Enabled: false`. The flag remains available only for an
intentional per-node opt-out that must not probe the endpoint.

Each logical dispatch is reported as one raw event. Source IP and normalized
destination address are sent as canonical plaintext inside the HTTPS JSON
request. Events are buffered and uploaded every 5 seconds by default. v2node
does not classify probes or aggregate minute buckets; FMPanel owns both
operations. URL paths, query strings, payloads, DNS message bodies, process
names, and application package names are not collected.

The local bounded queue, retry backoff, durable batch ID, event ID, stream ID,
and sequence behavior remain fail-open. Once startup probing succeeds, a later
missing route (`404`), rate limit, or server failure keeps the batch queued and
retries. Authentication failures disable delivery for that batch without
affecting proxy forwarding.

Queue files use owner-only permissions and XChaCha20-Poly1305. The queue key is
derived from the current Server API key, so there is no separately provisioned
secret. Server API key rotation intentionally invalidates old queued batches;
all affected node entries must be reconfigured together.

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
