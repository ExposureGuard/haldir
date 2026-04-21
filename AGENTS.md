# AGENTS.md

Guidance for AI coding agents (Cursor, Codex, Aider, Claude Code,
Windsurf, Devin, Copilot Workspace, etc.) working on the Haldir
codebase. Read this before making changes. Same conventions a new
human engineer would be told on day one — just written in the form
every modern agent tool knows to load.

## What this project is

Haldir is the governance layer for AI agents: scoped sessions,
encrypted vault, immutable audit trail, RFC 6962 Merkle tamper-
evidence, SOC2 audit-prep evidence packs. Shipped as:

- Python Flask REST API (`api.py`, ~4,000 lines; single-file by design)
- Python SDK (`sdk/`) — sync + async HTTPX clients
- CLI (`cli.py`) — every API endpoint mirrored as a subcommand
- Landing + dashboard HTML (`landing/`)
- Optional MCP server (emerging; see `/.well-known/mcp/mcp.json`)

Primary working directory: the repo root. SQLite in dev, Postgres in
prod. Single-tenant model per API key; multi-tenancy at the DB row
level keyed on `tenant_id`.

## Run + build commands

| Task | Command |
|------|---------|
| Install deps | `pip install -r requirements.txt` |
| Run dev server | `python api.py` (or `haldir dev` via CLI) |
| Run full tests | `python -m pytest tests/ -q` |
| Run property tests | `python -m pytest tests/test_merkle_properties.py -v` |
| Run Merkle benchmarks | `python bench_merkle.py --tree-size 10000` |
| Type-check | `mypy api.py haldir_*.py` |
| Build Docker image | `docker build -t haldir .` |
| Apply DB migrations | `python -c "import haldir_migrate; haldir_migrate.apply_pending('haldir.db')"` |

## Where things live

```
api.py                           — Flask app, every REST route
haldir_merkle.py                 — RFC 6962 primitives (stdlib only)
haldir_audit_tree.py             — Tenant-scoped STH + proofs over audit_log
haldir_demo_tamper.py            — /demo/tamper adversarial demo
haldir_compliance.py             — Evidence pack builder + HTML/markdown render
haldir_compliance_score.py       — Audit-prep readiness score
haldir_compliance_scheduler.py   — Recurring evidence delivery
haldir_db.py                     — SQLite + Postgres init/schema
haldir_migrate.py                — Versioned schema migrations
haldir_gate/, haldir_vault/, haldir_watch/  — Core governance primitives
haldir_scopes.py                 — Scope vocabulary + @require_scope decorator
haldir_openapi.py                — OpenAPI 3.1 spec auto-generation
haldir_export.py                 — SIEM / audit-archive streaming exports
haldir_email.py                  — Evidence-pack email delivery
haldir_idempotency.py            — Stripe-style idempotency keys
haldir_health.py                 — /livez + /readyz probe logic
sdk/                             — Python client SDKs
cli.py                           — Argparse-based CLI entry point
landing/                         — Static HTML + CSS for public site
tests/                           — pytest suite (500+ tests)
migrations/                      — Versioned SQL files
.well-known/                     — Agent discovery (MCP, security.txt, ai.txt)
```

## Conventions

- **Python 3.12+.** Type hints on all new code. `from __future__ import annotations` at the top of new modules.
- **Line length** ~88 chars; we don't block on it but the codebase trends short.
- **Imports** grouped stdlib → third-party → haldir-local, blank line between groups.
- **Error responses** go through `api._json_error(code, message, status, **extra)` so shape is uniform: `{"error", "code", "request_id", ...}`.
- **New endpoints** need: `@require_api_key` + `@require_scope("resource:action")` + (if JSON body) `@validate_body(schema)`. Pick scopes from `haldir_scopes.SCOPE_VOCABULARY`.
- **Audit-relevant writes** should call `watch.log_action(...)` so the hash chain covers them.
- **DB access** goes through `haldir_db.get_db(DB_PATH)`. Works against SQLite or Postgres; never write dialect-specific SQL outside that module.
- **Tests** live under `tests/`, named `test_<feature>.py`. Use `haldir_client` + `bootstrap_key` fixtures from `conftest.py` for HTTP tests; don't wipe `api_keys` or rely on module-level `HALDIR_DB_PATH` tricks (api.DB_PATH is frozen at first import).
- **When adding a test module that mints sessions**, add the standard autouse `_lift_agent_cap` fixture so the free-tier agent-count limit doesn't cross-contaminate tests (see `tests/test_compliance_score.py` for the pattern).
- **No emojis in code or drafted content.** Comments explain *why*, not *what*.
- **Never commit** secrets, `.env`, production DBs, or files matching `.gitignore`. The ignore list includes several private strategy docs — don't accidentally re-add them.

## Public API contract (don't break)

The following surfaces are public commitments and need migration notes if they change:

- REST endpoints under `/v1/` (listed in `openapi.json`)
- `haldir` Python SDK class shapes (`HaldirClient`, `HaldirAsyncClient`, exceptions)
- The STH format + RFC 6962 verification semantics (customers verify proofs offline with the same bytes)
- Webhook signature algorithm + canonical form (`haldir_watch.webhooks.canonicalize`)
- Scope vocabulary in `haldir_scopes.SCOPE_VOCABULARY`
- OpenAPI `operationId`s (codegen tools build SDKs against these)

## Operations that need human confirmation

Don't run these autonomously:

- `git push`, `git reset --hard`, force-push, `git rebase -i`
- Publishing to PyPI (`twine upload`)
- Writing to the production `.env` or Railway config
- Deleting migrations that have run in prod
- Anything that sends real email/webhooks to non-`@haldir.xyz` addresses
- Wiping `haldir.db` or any non-`/tmp/` database

## What to do if you're stuck

Prefer these over bypasses:

- If tests fail, fix the root cause, don't add `# noqa` or skip the test.
- If a linter rule fires, fix the code or propose a change to the linter config — don't disable per-line.
- If a commit hook blocks, fix the underlying issue rather than passing `--no-verify`.
- If you can't figure out whether something is safe, leave it for a human reviewer.

## Agent-visible discovery surface

This project is agent-discoverable on purpose. If you're an agent
building a tool list, the canonical entry points are:

- `/llms.txt` — plain-text summary for LLMs
- `/llms-full.txt` — extended context (every endpoint + examples)
- `/openapi.json` — OpenAPI 3.1 spec
- `/.well-known/ai-plugin.json` — legacy OpenAI plugin manifest
- `/.well-known/ai.txt` — authorship + data-use statement
- `/.well-known/mcp/mcp.json` — MCP server manifest
- `/.well-known/mcp/server-card.json` — human-readable server card
- `/.well-known/x402.json` — x402 paid-resource manifest (agentic.market compatible)
- `/v1/x402/manifest` — same content as well-known, preferred by some crawlers

For the adversarial demo that proves the tamper-evidence claim: `/demo/tamper`.

For agent-to-agent commerce: `/v1/x402/tree-head`, `/v1/x402/inclusion-proof/<entry_id>`, `/v1/x402/evidence-pack` — USDC-priced via x402 v2 (gated behind `HALDIR_X402_ENABLED=1`).
