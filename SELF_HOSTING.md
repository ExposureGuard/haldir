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
curl http://localhost:8000/health
# → {"ok": true}
```

You now have Haldir running on `http://localhost:8000`.

---

## Create your first API key

If you set a `HALDIR_BOOTSTRAP_TOKEN` in `.env`:

```bash
curl -X POST http://localhost:8000/v1/keys \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: $HALDIR_BOOTSTRAP_TOKEN" \
  -d '{"name": "my-first-key"}'
```

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

The API is stateless. Run as many replicas as you want behind a load balancer — they all point at the same Postgres. Use `--workers 4 --threads 8` on gunicorn for per-instance throughput.

### 6. Monitoring

Haldir exposes `/health` (liveness) and `/v1/metrics` (platform metrics). Wire these into your monitoring stack.

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

---

## Community

- **Issues:** https://github.com/ExposureGuard/haldir/issues
- **Discussions:** https://github.com/ExposureGuard/haldir/discussions
- **Security reports:** security@haldir.xyz (see `.well-known/security.txt`)

Found a bug in self-host? Open an issue. Want a feature? Open a discussion. Want to contribute? See `CONTRIBUTING.md`.
