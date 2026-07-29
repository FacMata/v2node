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
the expected invalid-payload code. Missing routes and authentication failures
are skipped without affecting node startup.

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

Set `Telemetry.Enabled` to `false` for an explicit per-node opt-out. Missing
`Telemetry` configuration means enabled.

Source IP is sent as canonical plaintext inside the HTTPS JSON request.
FMPanel converts it to central HMAC and anonymous prefix before ClickHouse
publication. Unknown destination names, URL paths, query strings, payloads,
and full browsing logs never leave v2node.

The local bounded queue, retry backoff, durable batch ID, bucket ID, stream ID,
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
