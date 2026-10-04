# Configuration

Every environment variable Haldir reads, what it does, and what it defaults to.

This file exists because the previous answer was "grep the source": `.env.example`
documented eight of the forty-six `HALDIR_*` names the code reads, and the
other thirty-eight were discoverable only by reading the modules that use them.
`tests/test_configuration_docs.py` now scans the tree and fails when a variable
is read but not listed here, so this cannot quietly go stale again.

Most of these are optional. Haldir runs with none of them set: SQLite, no
email, no metrics endpoint, no transparency mirror, no tracing. The tables
below say what turning each one on does.

## Start here

| Variable | Default | What it does |
|---|---|---|
| `HALDIR_ENCRYPTION_KEY` | *(none)* | Vault master key (AES-256-GCM, base64url). **Losing it loses every stored secret.** Unset, a process-local key is generated and a warning is logged — fine for a demo, wrong for anything else. |
| `HALDIR_BOOTSTRAP_TOKEN` | *(empty)* | When set, `POST /v1/keys` requires it (`X-Bootstrap-Token` header or `bootstrap_token` body field). Protects the first key on an instance that has none. |
| `HALDIR_BASE_URL` | `https://haldir.xyz` | This instance's public origin. Everything the discovery documents (`/llms.txt`, `/.well-known/agent.json`, the OpenAPI spec) name is built from it. Unset on a self-hosted install, an agent following your agent card would follow it to ours. See SELF_HOSTING.md. |
| `DATABASE_URL` | *(empty)* | Postgres DSN (`postgresql://user:pass@host/haldir`). Set, Postgres is used; unset, SQLite at `HALDIR_DB_PATH`. |
| `HALDIR_DB_PATH` | `/data/haldir.db` when `/data` exists, else `haldir.db` | SQLite file. Ignored when `DATABASE_URL` is set. |

## Storage

| Variable | Default | What it does |
|---|---|---|
| `HALDIR_AUTO_MIGRATE` | *(off)* | `1` runs pending migrations when the app starts. Off by default so a deployment can run migrations as its own step, before traffic arrives. |
| `HALDIR_MIGRATIONS_DIR` | the packaged `migrations/` | Where migration `.sql` files live. |
| `HALDIR_DATA_DIR` | `~/.haldir` | Where the CLI keeps local state (a generated `encryption.key`, for instance). |

### Postgres pool and timeouts

Only read when `DATABASE_URL` is set. Every gunicorn worker has its own pool.

| Variable | Default | What it does |
|---|---|---|
| `HALDIR_PG_POOL_MIN` | `2` | Pool floor, so the second request does not pay cold-connect latency. |
| `HALDIR_PG_POOL_MAX` | `20` | Pool ceiling. Size to workers × expected concurrency, with headroom for Postgres' `max_connections`. |
| `HALDIR_PG_POOL_WAIT_S` | `10` | Seconds to wait for a free connection before failing the request. |
| `HALDIR_PG_SCHEMA_LOCK_WAIT_S` | `60` | How long a migration waits for the schema lock before giving up. |
| `HALDIR_PG_LOCK_TIMEOUT_MS` | `10000` | Server-side `lock_timeout`, applied on connect. |
| `HALDIR_PG_STATEMENT_TIMEOUT_MS` | `120000` | Server-side `statement_timeout`, applied on connect. |

## Logging

| Variable | Default | What it does |
|---|---|---|
| `HALDIR_LOG_LEVEL` | `INFO` | Root log level. |
| `HALDIR_LOG_JSON` | decided by destination | Unset, output is JSON when stderr is not a TTY (containers, pipes) and readable lines when it is. `0` forces lines, anything else forces JSON. |
| `HALDIR_LOG_SILENT` | *(off)* | `1` installs a null handler — no log output at all. Used by tests and benchmarks. |
| `HALDIR_LOG_HEALTHZ` | *(off)* | `1` includes `/healthz` in access logs, which are skipped by default as noise. |
| `HALDIR_MCP_LOG_LEVEL` | `INFO` | Log level of the stdio MCP server (its logs must go to stderr — stdout is the protocol). |
| `HALDIR_TRACING_ENABLED` | *(off)* | `1`, with `opentelemetry-api` installed, emits real spans. Without either, tracing calls compile to no-ops. |

## Tamper-evidence

The audit log's tree heads are signed. These decide with what, and where the
proofs are anchored outside this database.

| Variable | Default | What it does |
|---|---|---|
| `HALDIR_STH_ALGORITHM` | *(empty — HMAC-SHA256)* | `ed25519` signs tree heads with Ed25519 instead, which lets an auditor verify with only the public key. |
| `HALDIR_TREE_SIGNING_KEY` | *(none)* | The HMAC key, when using the default algorithm. |
| `HALDIR_TREE_SIGNING_KEY_ED25519` | *(none)* | Base64 Ed25519 private key (PKCS#8/DER), when signing with Ed25519. |
| `HALDIR_TREE_SIGNING_KEY_ED25519_SEED` | *(none)* | The same key as a raw 32-byte seed, for tooling that stores seeds. |
| `HALDIR_TRANSPARENCY_MIRROR` | `none` | Where every signed tree head is mirrored: `file:/path` (append-only JSONL), `http:URL` (POST, records the response), or `rekor[:url]` (Sigstore Rekor). Opt-in; `none` is a no-op. |
| `HALDIR_TRANSPARENCY_TIMEOUT` | `10` | Seconds for the HTTP and Rekor backends. |
| `HALDIR_REKOR_URL` | the public Rekor instance | Which Rekor to verify stored receipts against. |
| `HALDIR_ENCRYPTION_KEY_PREVIOUS` | *(none)* | The outgoing key during a rotation: reads fall back to it so nothing re-enters secrets. See the rotation procedure in SELF_HOSTING.md. |
| `HALDIR_ENCRYPTION_KEY_LEGACY` | *(none)* | The name this shipped under; accepted as an alias for the same fallback. |

## HTTP surface

| Variable | Default | What it does |
|---|---|---|
| `HALDIR_METRICS_TOKEN` | *(none)* | `/v1/metrics` refuses to serve **at all** while this is unset — an unauthenticated Prometheus endpoint leaks internal telemetry. The scraper passes it as `?token=` or a bearer token. |
| `HALDIR_ORIGIN_SECRET` | *(none)* | When the app runs behind a proxy, the trusted edge signs the client address it saw (`X-Haldir-Client-IP` + `X-Haldir-Origin-Secret`); the claim is believed only when this secret verifies. Unset, the client address is the socket peer, as before. See SELF_HOSTING.md. |

## Outbound requests

Haldir refuses to send a webhook or a proxy upstream at a private address —
cloud metadata endpoints and your internal network are not reachable through
it. Scheme and credential checks are not relaxed by these.

| Variable | Default | What it does |
|---|---|---|
| `HALDIR_ALLOW_PRIVATE_OUTBOUND` | *(off)* | `1` permits private and loopback addresses. For an operator who owns both ends and is deliberately pointing at an internal service. |
| `HALDIR_ALLOW_PRIVATE_WEBHOOKS` | *(off)* | The original name, accepted as an alias so a deployment that set it keeps working. |

## MCP

| Variable | Default | What it does |
|---|---|---|
| `HALDIR_API_KEY` | *(none)* | The key the stdio MCP server sends. |
| `HALDIR_URL` | `https://haldir.xyz` | The instance the MCP proxy and client target. |
| `HALDIR_UPSTREAM_SERVERS` | *(none)* | JSON map of name → URL for proxy mode, e.g. `{"stripe": "http://localhost:3001"}`. Every call to a named upstream is checked against the session's scopes first. |

## x402 (pay-per-request proofs)

Off unless enabled. Exposes the audit primitives as paid resources so an agent
can buy a proof with USDC.

| Variable | Default | What it does |
|---|---|---|
| `HALDIR_X402_ENABLED` | *(off)* | `1` exposes the `/v1/x402/*` surface; otherwise it answers 503. |
| `HALDIR_X402_PAY_TO` | *(none)* | The address that receives payment. Required when enabled — with test mode off, a request without it is refused rather than paying nobody. |
| `HALDIR_X402_ASSET` | USDC on Base mainnet | Asset contract. |
| `HALDIR_X402_NETWORK` | `eip155:84532` (Base Sepolia) | CAIP-2 network id. |
| `HALDIR_X402_TEST_MODE` | *(off)* | `1` accepts any structurally-valid payment header — for local development, never on a deployment that expects money. |
| `HALDIR_X402_FACILITATOR_URL` | `https://x402.org/facilitator` | The facilitator that settles payments. |

## Email and scheduled delivery

Used by compliance evidence packs: recurring delivery, and the `mailto:` a
failed demo run prints. Unset, email is simply unavailable and the API says so
(`smtp_unconfigured`) rather than failing silently.

| Variable | Default | What it does |
|---|---|---|
| `HALDIR_SMTP_HOST` | *(none)* | Hostname, e.g. `smtp.sendgrid.net`. This is the switch: without it, email is off. |
| `HALDIR_SMTP_PORT` | `587` | Port. |
| `HALDIR_SMTP_USER` | *(none)* | Username, when the relay wants one. |
| `HALDIR_SMTP_PASSWORD` | *(none)* | Password or API token. |
| `HALDIR_SMTP_FROM` | `noreply@haldir.xyz` | Sender address. Set it to your own domain — an address you do not control will fail SPF/DMARC at the receiver. |
| `HALDIR_SMTP_USE_TLS` | `1` | STARTTLS after EHLO. |
| `HALDIR_COMPLIANCE_SCHEDULER` | *(off)* | `1` starts the background scheduler that delivers evidence packs on their configured schedules. |

## Containers

`docker-compose.yml` reads `HALDIR_PORT` (default `8000`) for the **host** port
the API is published on; inside the container it is always 8080. The runbook in
SELF_HOSTING.md covers the rest of the compose surface (`POSTGRES_*`).

## Build and CI only

| Variable | Default | What it does |
|---|---|---|
| `HALDIR_SBOM_TIMESTAMP` | *(none)* | Pins the timestamp in a generated SBOM so two builds of the same tree produce byte-identical output. Only read by `scripts/gen_sbom.py`. |
