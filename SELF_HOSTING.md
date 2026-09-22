# Self-hosting Haldir

Haldir is open-source under the MIT license. You can run the full governance layer — Gate, Vault, Watch, Proxy — on your own infrastructure for free, forever.

This guide gets you from zero to a running instance in about 5 minutes.

**Feature parity:** Self-hosted Haldir has every feature the hosted service has. No hidden code, no paywalled modules, no phone-home telemetry.

---

## Why self-host?

- **Data sovereignty** — every secret, audit entry, and session stays inside your perimeter
- **Compliance** — deploy inside your SOC 2 / HIPAA / GDPR boundary without a vendor review
- **Air-gapped environments** — run without any network egress if your infra requires it
- **Cost** — free forever; you only pay for compute you already have
- **Trust** — every byte of logic is inspectable source code

You can always migrate to the hosted service at [haldir.xyz](https://haldir.xyz) later — same API, same SDKs, `DATABASE_URL` is the only thing that changes.

---

## Prerequisites

- Docker 24+ with Compose v2
- An `openssl`-capable shell (for generating encryption keys)
- A box with at least 512 MB RAM + 1 GB disk

That's it.

---

## 5-minute setup

```bash
# 1. Clone
git clone https://github.com/ExposureGuard/haldir.git
cd haldir

# 2. Generate an encryption key for Vault
python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
# Copy the output

# 3. Write .env
cp .env.example .env
# Open .env, paste the key as HALDIR_ENCRYPTION_KEY, save

# 4. Start the stack
docker compose up -d

# 5. Verify
curl http://localhost:8000/healthz
# → {"alive": true, "status": "ok", "service": "haldir", ...}
```

You now have Haldir running on `http://localhost:8000`.

---

## Create your first API key

If you set a `HALDIR_BOOTSTRAP_TOKEN` in `.env`, send it in the **body** as
`bootstrap_token`:

```bash
curl -X POST http://localhost:8000/v1/keys \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"my-first-key\", \"bootstrap_token\": \"$HALDIR_BOOTSTRAP_TOKEN\"}"
```

(An `X-Bootstrap-Token` header looks like the obvious spelling, but nothing
reads it — the server returns 401 and the key is not created.)

If you left it empty, the first key creation is open:

```bash
curl -X POST http://localhost:8000/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "my-first-key"}'
```

Save the returned `key` value (starts with `hld_`). You'll need it for every subsequent call.

---

## Try it

```bash
export HALDIR_API_KEY='hld_...'

# Create a scoped session
curl -X POST http://localhost:8000/v1/sessions \
  -H "Authorization: Bearer $HALDIR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "my-agent", "scopes": ["read","execute"], "spend_limit": 5}'
```

Or point the Python SDK at your instance:

```python
from haldir import HaldirClient

client = HaldirClient(
    api_key="hld_...",
    base_url="http://localhost:8000",   # ← your instance
)

session = client.create_session("my-agent", scopes=["read","execute"], spend_limit=5)
print(session)
```

The framework integrations all accept a `base_url` parameter too — `langchain-haldir`, `crewai-haldir`, `@haldir/ai-sdk` all work identically against self-hosted and hosted Haldir.

---

## Production deployment

The basic `docker-compose.yml` is suitable for single-node deployments. For production, you'll want:

### 1. Externalize the database

Replace the compose Postgres with a managed service (RDS, Cloud SQL, Neon, Supabase, Postgres on k8s, etc.). Set:

```
DATABASE_URL=postgresql://user:pass@your-host:5432/haldir
```

Remove the `postgres` service + `depends_on` block from `docker-compose.yml`.

### 2. Put a TLS terminator in front

Haldir's container speaks plain HTTP. In production, front it with nginx / Caddy / Cloudflare / your load balancer.

### 3. Back up the encryption key

`HALDIR_ENCRYPTION_KEY` is the master key for Vault. If you lose it, every stored secret is unrecoverable. Put it in AWS KMS / GCP Secret Manager / Vault / 1Password Business and inject at deploy time.

### 4. Back up Postgres

Standard Postgres backups. Audit entries are written-once hash-chained — preserving history is important for tamper-evidence.

### 5. Horizontal scaling

The API holds no session state — every request resolves its tenant from the
database — so you can run as many replicas as you want behind a load
balancer, all pointed at the same Postgres. Use `--workers 4 --threads 8` on
gunicorn for per-instance throughput.

**One caveat worth knowing before you size it:** the hourly per-key rate
limiter keeps its counters in process memory, so each replica enforces its
own. Run four replicas and a key gets four times the quota before anything
is refused. Audit entries, spend caps, session state and idempotency keys
are all database-backed and unaffected — this is the rate limiter only. If
you are relying on the tier limits as a hard ceiling rather than a
best-effort throttle, run a single replica or front it with a shared limiter
at the load balancer.

### 6. Monitoring

Haldir exposes `/healthz` (liveness) and `/v1/metrics` (platform metrics). Wire these into your monitoring stack.

---

## Kubernetes

A minimal Helm-style deployment:

```yaml
# haldir.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: haldir
spec:
  replicas: 2
  selector: { matchLabels: { app: haldir } }
  template:
    metadata: { labels: { app: haldir } }
    spec:
      containers:
        - name: haldir
          image: ghcr.io/exposureguard/haldir:latest
          ports: [{ containerPort: 8080 }]
          env:
            - name: DATABASE_URL
              valueFrom: { secretKeyRef: { name: haldir-secrets, key: database_url } }
            - name: HALDIR_ENCRYPTION_KEY
              valueFrom: { secretKeyRef: { name: haldir-secrets, key: encryption_key } }
          # Liveness: restart the pod if the process wedges.
          # Readiness: withhold traffic until migrations have run.
          # These are the two questions /livez and /readyz exist to answer
          # separately — a pod that is alive but still migrating should not
          # be receiving requests.
          livenessProbe:
            httpGet: { path: /livez, port: 8080 }
            initialDelaySeconds: 10
            periodSeconds: 20
          readinessProbe:
            httpGet: { path: /readyz, port: 8080 }
            initialDelaySeconds: 5
            periodSeconds: 10
            failureThreshold: 6
---
apiVersion: v1
kind: Service
metadata: { name: haldir }
spec:
  selector: { app: haldir }
  ports: [{ port: 80, targetPort: 8080 }]
```

```bash
kubectl create secret generic haldir-secrets \
  --from-literal=database_url='postgresql://...' \
  --from-literal=encryption_key='your-fernet-key'
kubectl apply -f haldir.yaml
```

---

## Upgrading

Self-hosted Haldir is versioned with the same tags as the hosted service. Pinning to `:latest` is fine for dev but use semver tags in production:

```bash
docker compose pull
docker compose up -d
```

Release notes live at [github.com/ExposureGuard/haldir/releases](https://github.com/ExposureGuard/haldir/releases).

Schema migrations are idempotent and run automatically on boot.

---

## Rotating the encryption key

The Vault encrypts every secret with `HALDIR_ENCRYPTION_KEY`. Rotating it — because someone with access left, or because your policy says so — is a four-step procedure with no downtime and no re-entry of secrets.

Every stored secret records which key encrypted it, so the server can hold your old and new keys at once and rewrite the store while it keeps serving reads.

**1. Generate the new key.**

```bash
python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
```

**2. Point the environment at it, keeping the old one.** In `.env`:

```bash
HALDIR_ENCRYPTION_KEY=<the new key>
HALDIR_ENCRYPTION_KEY_PREVIOUS=<the old key>
```

Restart. New writes use the new key; existing secrets still decrypt with the old one. Verify nothing broke before going further:

```bash
curl -H "Authorization: Bearer $HALDIR_API_KEY" \
     -H "X-Session-ID: $SESSION_ID" \
     https://your-haldir/v1/secrets/some-existing-secret
```

**3. Rewrite the store.**

```bash
# See what would happen, changing nothing
curl -X POST -H "Authorization: Bearer $HALDIR_API_KEY" \
     "https://your-haldir/v1/vault/rotate?dry_run=true"

# Do it
curl -X POST -H "Authorization: Bearer $HALDIR_API_KEY" \
     https://your-haldir/v1/vault/rotate
```

This endpoint takes **no key in the request body** — deliberately. The new key reaches the server through its environment, never over HTTP, so it cannot end up in a proxy log or a shell history. An endpoint that accepted a key would also be accepting a key the server was never configured with.

Safe to interrupt and re-run: each secret is rewritten on its own, and until the pass finishes the old key is still loaded, so a crash leaves a vault that reads correctly rather than one that does not. Re-running finishes the job and rewrites nothing twice.

**4. Confirm, then drop the old key.**

```bash
curl -H "Authorization: Bearer $HALDIR_API_KEY" https://your-haldir/v1/vault/keys
```

You get which keys the ciphertext actually needs and how many blobs each covers:

```json
{
  "keys": [{"key_id": "9f2c…", "role": "primary"}],
  "blobs_by_key": {"9f2c…": 412},
  "unreadable_blobs": 0,
  "total_blobs": 412
}
```

Retire the old key **only** when `blobs_by_key` no longer lists it. Then remove `HALDIR_ENCRYPTION_KEY_PREVIOUS` and restart. Keeping a key loaded that nothing needs is a key you still have to protect.

**If the response is `207` rather than `200`,** some secrets could not be read — usually a key that was retired early. The report names them and the reason; nothing was lost, and restoring the missing key and re-running fixes it. Do not treat a 207 as success.

```bash
# Which keys are still needed?
curl -H "Authorization: Bearer $HALDIR_API_KEY" https://your-haldir/v1/vault/keys

# Re-key: needs the `vault:rotate` scope. `vault:write` is NOT enough —
# authority over the secrets is separate from authority over the key
# protecting them.
curl -X POST -H "Authorization: Bearer $ADMIN_KEY" https://your-haldir/v1/vault/rotate
```

**Upgrading from a build older than this one** needs no action. Pre-existing secrets were written before ciphertext carried a key id, and the server opens those with the key it was started with — which, on an ordinary upgrade, is the same key that wrote them. If you had already changed `HALDIR_ENCRYPTION_KEY` some other way, set `HALDIR_ENCRYPTION_KEY_LEGACY` to the key that produced them; the error message will tell you.

---

## Troubleshooting

**API returns `503 encryption key not configured`**
You didn't set `HALDIR_ENCRYPTION_KEY` in `.env`. Generate one:
```bash
python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
```

**`docker compose up` fails with `database "haldir" does not exist`**
Happens if Postgres volume was initialized under different credentials. Fix:
```bash
docker compose down -v    # WARNING: deletes data
docker compose up -d
```

**Want to wipe and start fresh**
```bash
docker compose down -v    # -v removes the named volume too
```

**Schema is wrong / corrupted**
The API auto-applies migrations on boot. Force a re-check:
```bash
docker compose restart api
```

---

## Self-hosted vs Hosted (haldir.xyz)

| | Self-hosted | Hosted (haldir.xyz) |
|---|---|---|
| Price | Free forever | Free tier + paid plans |
| Feature set | Everything | Everything |
| You run | API + Postgres | Nothing |
| Data location | Your infra | US region |
| SLA | What you build | 99.9% |
| Support | Community (GitHub Discussions) | Email + chat |
| Compliance | Whatever your infra has | SOC 2 (in progress) |
| Migration | `DATABASE_URL` is the only thing that changes | — |

Whichever you pick, the API, SDKs, and framework integrations are identical.

### Tell your instance where it lives

Set `HALDIR_BASE_URL` to your instance's public origin:

```bash
HALDIR_BASE_URL=https://haldir.yourcompany.com
```

Haldir serves a set of discovery documents — `/llms.txt`, `/sitemap.xml`,
`/.well-known/agent.json`, `/.well-known/ai.txt`, `/robots.txt`, and the
OpenAPI spec at `/openapi.json`. They exist so that **agents** can find and
call your instance without a human reading a README first, and they name
absolute URLs.

Unset, those URLs are `https://haldir.xyz` — which is correct on the hosted
service and wrong on yours. An agent that reads your agent card and follows
it would send your credentials and your data to us. It would work. That is
the problem.

Setting `HALDIR_BASE_URL` makes your instance describe itself instead.
It also sets `servers` in the OpenAPI spec, which is where a generated
client sends every request.

Leave it unset and nothing changes — the documents are served exactly as
they ship.

Set `HALDIR_BASE_URL` if you are self-hosting. It takes one line and it is
the difference between an agent talking to you and an agent talking to your
vendor.

---

## Community

- **Issues:** https://github.com/ExposureGuard/haldir/issues
- **Discussions:** https://github.com/ExposureGuard/haldir/discussions
- **Security reports:** security@haldir.xyz (see `.well-known/security.txt`)

Found a bug in self-host? Open an issue. Want a feature? Open a discussion. Want to contribute? See `CONTRIBUTING.md`.
