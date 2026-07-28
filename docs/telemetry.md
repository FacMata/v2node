# Connection telemetry

Telemetry is disabled by default and is configured independently for each
entry in `Nodes`. Secrets are referenced by environment-variable name and
must not be written into `config.json`.

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
        "KeyID": "01JTELEMETRYKEY00000000000",
        "SecretEnv": "V2NODE_TELEMETRY_SECRET_123",
        "SourceSealingPublicKey": "base64url-32-byte-x25519-public-key",
        "SourceSealingKeyVersion": 1,
        "ClassifierCatalogPath": "/etc/v2node/telemetry-catalog.json",
        "ClassifierVerificationKey": "base64url-32-byte-ed25519-public-key",
        "QueueDirectory": "/var/lib/v2node/telemetry/123",
        "QueueKeyEnv": "V2NODE_TELEMETRY_QUEUE_KEY_123",
        "QueueKeyVersion": 1
      }
    }
  ]
}
```

Both secret environment variables contain unpadded base64url:

- `SecretEnv`: at least 32 random bytes, issued for this node/key ID only;
- `QueueKeyEnv`: exactly 32 random bytes for local XChaCha20-Poly1305 records.

The catalog file is an envelope:

```json
{
  "catalog": {
    "version": "2026-07-29.1",
    "valid_until": "2026-08-05T00:00:00Z",
    "rules": [
      {
        "id": "cloudflare_one_http",
        "host": "1.1.1.1",
        "match_suffix": false,
        "ports": [80],
        "protocols": ["http"],
        "confidence": "high",
        "enabled": true
      }
    ]
  },
  "signature": "base64url-ed25519-signature"
}
```

The Ed25519 signature covers the exact raw JSON bytes used as the value of
`catalog`. Catalog hosts must already be canonical lowercase ASCII. An invalid
or expired catalog never blocks forwarding; an expired catalog classifies
destinations as `unknown`.

Optional bounds use these defaults:

| Field | Default |
|---|---:|
| `QueueMaxBytes` | 268435456 |
| `QueueMaxAgeSeconds` | 21600 |
| `BufferSize` | 4096 |
| `FlushIntervalSeconds` | 5 |
| `RequestTimeoutSeconds` | 10 |
| `RetryMinSeconds` / `RetryMaxSeconds` | 1 / 60 |
| `ShutdownTimeoutSeconds` | 5 |

Core/config reload keeps the existing telemetry manager, encrypted queue,
stream ID and sender alive, then rebinds the new dispatcher. Changes to
telemetry keys, catalog paths or queue settings therefore require a process
restart.
