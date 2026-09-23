# Haldir CLI

Everything the platform does, from the terminal. Installs with the package:

```bash
pip install haldir
haldir --help
```

Every command has its own help — `haldir audit --help`, `haldir session
create --help`.

- [Connecting to an instance](#connecting-to-an-instance)
- [Running an instance](#running-an-instance)
- [Sessions and permissions](#sessions-and-permissions)
- [Secrets](#secrets)
- [Payments](#payments)
- [Audit](#audit)
- [Proxy](#proxy)
- [API keys](#api-keys)
- [Operations](#operations)
- [Webhooks](#webhooks)
- [Retention](#retention)
- [Compliance](#compliance)
- [Migrations](#migrations)
- [MCP](#mcp)
- [JSON output, and which commands have it](#json-output-and-which-commands-have-it)

---

## Connecting to an instance

Two global flags, accepted by every command:

```bash
haldir --url http://127.0.0.1:8000 --key hld_xxx overview
```

They default to `HALDIR_BASE_URL` and `HALDIR_API_KEY` in the environment, and
below that to the config file `haldir login` writes.

| | |
|---|---|
| `haldir login` | Store an API key and URL. `--key`, `--url`; prompts if omitted. |
| `haldir config show` | Show the current config. |

`haldir serve` points the CLI at the instance it starts, so after it you can
run any command without `--url` or `--key`.

## Running an instance

| | |
|---|---|
| `haldir serve` | A local Haldir on SQLite — no Docker, no Postgres, no account. Generates an encryption key, applies the schema, mints an API key, points the CLI at it, and serves. |
| `haldir init <dir>` | Write a `.env` with a fresh encryption key, for a Postgres deployment. `--force` overwrites. |
| `haldir dev` | Bring up the Docker Compose stack (Haldir + Postgres). `--down` stops it, `--reset` wipes volumes, `-f` runs in the foreground. |

`serve` flags: `--host` (default `127.0.0.1`), `--port` (default `8000`),
`--data-dir` (default `~/.haldir`), `--db`, and `--no-key` to skip minting a
key and leave the CLI config alone.

Use `serve` for a demo or an evaluation; use `init` + `dev` for anything
Postgres-backed.

## Sessions and permissions

A session is the unit of governance — an agent's identity, its scopes, and its
spend ceiling. Every other call references one.

```bash
haldir session create --agent my-agent --scopes read,execute --spend-limit 5.00
haldir session get ses_xxx
haldir session check ses_xxx execute
haldir session revoke ses_xxx
```

`check` is the one your wrapper calls before acting: it returns whether the
session may use that scope **right now**, so a revocation takes effect on the
next call rather than the next session.

## Secrets

Stored encrypted (AES-256-GCM, bound to tenant and name); agents retrieve them
through Haldir and never hold the raw value.

```bash
haldir secret store stripe_key sk_live_xxx
haldir secret get stripe_key
haldir secret list
haldir secret delete stripe_key
```

## Payments

```bash
haldir pay authorize --session ses_xxx --amount 29.99 --description "API subscription"
```

Authorizes against the session's spend cap. Over the cap it is **refused**, not
logged-and-allowed.

## Audit

The tamper-evident trail. Every entry is hashed into a chain, and the chain
into an RFC 6962 Merkle tree with Ed25519 Signed Tree Heads — so an auditor can
verify offline that history was not edited.

```bash
haldir audit log --session ses_xxx --tool stripe --action charge --cost 0.50
haldir audit trail --agent my-agent --limit 50
haldir audit stats
haldir audit spend
haldir audit export --format jsonl --out audit.jsonl
haldir audit verify                       # hash-chain integrity
```

Verification, for an auditor who does not trust the server:

```bash
haldir audit tree-head                    # the current Signed Tree Head
haldir audit prove aud_xxx                # inclusion proof for one entry
haldir audit verify-proof proof.json      # verify it offline
haldir audit consistency --first 100 --second 250
```

`verify-proof` is the one that matters: it takes the archived proof and
verifies it locally, against a tree head you already hold — no trust in the
running server required.

## Proxy

Enforcement for MCP tool calls. The agent connects to Haldir as its MCP server,
and every call is evaluated before it is forwarded.

```bash
haldir proxy register stripe https://mcp.example.com/stripe
haldir proxy tools
haldir proxy call stripe.charge --arg amount=29.99
haldir proxy policy add --type allow_list --tools list_customers,get_invoice
```

Policy types: `block_tool`, `allow_list`, `deny_list`, `spend_limit`,
`rate_limit`, `time_window`.

## API keys

```bash
haldir keys list
haldir keys create --name ci-runner
haldir keys revoke hld_abc123
```

The full key is shown once, at creation. Afterwards only the prefix is
available — `revoke` takes that prefix.

## Operations

```bash
haldir overview              # the dashboard, one screen
haldir overview --watch      # live, top-style
haldir top                   # the fleet console
haldir status                # component health, green/yellow/red
haldir ready                 # exits 0 or 1 — for CI and load balancers
haldir metrics               # Prometheus exposition
```

`ready` is the one to wire into a health check. `status` tells a human what is
wrong; `ready` answers yes or no.

## Webhooks

```bash
haldir webhooks deliveries              # recent attempts, with status codes
haldir webhooks rotate <id-or-url>      # rotate the HMAC secret
```

Rotation keeps the previous secret valid for an overlap window, so a receiver
can be updated without dropping events.

## Retention

```bash
haldir retention show                   # the window, and what a prune would remove
haldir retention set 90                 # days; 0 keeps everything
haldir retention prune                  # irreversible
haldir retention checkpoints            # what was pruned, and the signed root
```

`prune` is the only destructive command here. It leaves a signed checkpoint
committing to what it removed, so the trail stays verifiable across a prune.

## Compliance

```bash
haldir compliance evidence --out ./evidence/
haldir compliance schedules
```

Generates a proof-of-control pack for SOC2 workpapers — the audit evidence, the
tree head, and the verification material, in one archive.

## Migrations

```bash
haldir migrate up              # apply pending
haldir migrate status          # applied and pending
haldir migrate verify          # file-vs-record checksum drift
```

`--db-path` overrides `HALDIR_DB_PATH`.

## MCP

```bash
haldir mcp config              # a ready-to-paste client config
haldir mcp serve               # run the stdio server
```

`mcp config` prints the `mcpServers` block for Claude Desktop, Cursor, Windsurf
and anything else that speaks MCP over stdio — pointed at whichever instance
your CLI is configured for.

---

## JSON output, and which commands have it

**Not every command takes `--json`.** It is worth knowing which do before
scripting against them:

| Has `--json` | Does not |
|---|---|
| `overview` | `session get`, `session create` |
| `status` | `audit trail`, `audit verify — see below` |
| `ready` | `secret list` |
| `keys list` | `metrics` |
| `webhooks deliveries` | `compliance evidence` |
| `retention show` | `migrate status` |
| | `proxy tools` |

Run `haldir <command> --help` to check before you depend on it. If you are
scripting against the API rather than the CLI, `/openapi.json` on any instance
is the complete and authoritative surface.

### Exit codes

`haldir ready` is the one with a defined contract: **0 when the instance is
healthy, non-zero otherwise.** That is what makes it usable as a container
health check or a CI gate; the other commands exit non-zero on error but do not
promise more than that.
