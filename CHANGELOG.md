# Changelog

All notable changes to Haldir are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.1] — 2026-09-23

### Fixed

- **`haldir secret get` crashed before it made a request.** `APIClient.request()`
  supplies its own `headers=`, so a caller passing one as well was a duplicate
  keyword argument rather than an override, and `cmd_secret_get` — the only
  call site that passes headers — raised `TypeError` every time. Not
  conditionally: the `headers` dict is passed whether or not `--session` was
  given, so the command was unreachable in full.

### Documentation

- **Six examples in `CLI.md` used the wrong flag shapes** — `session check`
  takes `--scope`, `pay authorize` and `audit log` take the session id
  positionally, `audit consistency` takes two positional sizes, `proxy call`
  takes `--args` as a JSON object, and `webhooks rotate` takes a numeric id.
  Found by running the commands rather than reading the help.

## [0.4.0] — 2026-09-23

The "provable boundaries" release. Two authorization failures closed — one
cross-tenant, where any tenant could read *and approve* any other tenant's
requests — plus the SSRF fix, and the first tooling built for outside testers.

The theme is one this project keeps meeting: **two halves of an interface that
each look correct alone, and nothing comparing them.** A schema and a route. A
declaration file and an implementation. A build-context list and a gitignore. A
scanner and the source it scans. Every fix below carries a test that *is* the
comparison, checked in the negative direction too — a guard that cannot fail is
worse than none.

### Security

- **Cross-tenant isolation.** Any tenant could read and approve any other
  tenant's requests, and every tenant's webhooks received every tenant's events.
- **The proxy would fetch any URL a tenant registered.** `register_upstream`
  took a URL, stored it and fetched it during tool discovery — no scheme check,
  no address check — and returned part of the response body in the registration
  reply. Webhooks and approvals already ran `safe_outbound_url`; the proxy did
  not call it. Now guarded at registration and at both fetch sites, with
  redirects no longer followed (a public URL answering 302 to loopback passes a
  registration-time check and is then fetched at the address it redirected to).
- **An MCP approval argument was accepted, validated, and silently discarded** —
  the third instance of that shape in this tree, after the SDK `ttl` and the JS
  `denyRequest` reason.

### Added

- **`haldir_probes`** — a disposable fixture for the three properties a
  reviewer named as the ones they would attack first: mid-call revocation,
  timeout-after-commit retries, and audit read-back after reconnect. Each probe
  carries a control, so a check that always answers "no" cannot pass, and the
  read-back probe edits a row behind the server's back to prove the verifier
  can fail.
- **`demo_quickstart`** — one file that bootstraps a throwaway virtualenv, runs
  the probes, and deletes everything. Also the entry point for the bundled demo
  binary.
- **A break-it playground on `/demo`** — four steps walk the happy path, then
  three try to break it: spend past the cap, revoke the session mid-flight, act
  after revocation.

### Fixed

- **`from haldir import ...` had never worked**, and every published example
  used it — the README, the integration READMEs, six blog posts, the CHANGELOG.
  The distribution is `haldir`; it shipped no module by that name.
- **The quickstart animation imported a class that does not exist** (`Haldir`,
  for `HaldirClient`) and printed a field the response does not contain. It also
  advertised `0.3.0` for two releases.
- **A permanently dead webhook was counted as a successful one.**
- **An omitted `ttl` was sent as `null`**, so two integrations' quickstarts
  400'd on the first call.
- **A denial's reason was silently discarded** by the JS SDK, and eight of its
  methods had no types.
- **Private notes were baked into the published image**, and the Glama
  container never started.
- **Both npm packages declared MIT and shipped no license file.**
- **The agent card undercounted the tools**, and the sitemap omitted six posts.
- **`first thirty seconds`** — logs went to stdout and the demo went unmentioned.
- **Dead-code sweep**, plus a correctness lint gate and the integration suites
  CI never ran.

## [0.3.2] — 2026-09-21

The "Postgres correctness" release. Haldir's documented enterprise backend —
the one `SELF_HOSTING.md` tells you to deploy — carried a set of bugs that were
invisible on SQLite and live on Postgres. Eight are fixed here, including one
that made every secret unreadable after a key rotation, and one that silently
left the audit chain's anti-fork constraint uncreated. Provable audit is the
central claim of this product; it now holds on the backend enterprises are
actually told to run.

### Fixed — Postgres

- **Key rotation made every secret unreadable.** `_parse_blob` compared a
  psycopg2 `memoryview` (format `'c'`) against `bytes`, so a rotated key never
  matched. Rotation is the operation you perform *because* you care about key
  hygiene, and it was destroying the secrets it exists to protect.
- **The audit chain's uniqueness constraint could fail silently.** The
  audit-seq migration raised `AttributeError` on a raw connection, so the
  anti-fork index was never created — leaving the append-only chain forkable.
- **`_exec` returned `execute()`'s result** — a cursor on sqlite3, `None` on
  psycopg2 — which concealed the failure above instead of surfacing it.
- **A failed catalogue probe aborted the transaction**, so every later
  statement in the same block failed for an unrelated reason.
- **Money was a 4-byte `REAL`.** `REAL` means different things on the two
  backends; 1234.56 round-tripped as 1234.56005859375.
- **`PgConnectionWrapper` had no `rollback`**, so the audit append's retry
  path raised instead of retrying.
- **A pooled connection was returned with a transaction still open.**
- **Pool exhaustion destroyed in-flight connections instead of waiting**, and
  schema init took an exclusive lock on every start with no timeout — two
  ways a busy or freshly-restarted instance could wedge itself.

### Fixed — Packaging

- **The wheel shipped no application content.** An installed Haldir answered
  500 on `/llms.txt`, the agent card, `/AGENTS.md`, `/robots.txt`,
  `/sitemap.xml`, the docs, the blog and the demo — the whole discovery
  surface, which is how an agent or a registry works out that Haldir exists.
- **The wheel is built from the sdist, and the sdist listed three modules.**
  Fixing the wheel's include list twice changed nothing for that reason.
  `tests/test_packaging.py` now asserts every entry-point module is present.
- **Gunicorn had nowhere to write its control socket** in the container image.

### Added

- **`haldir serve`** — a working instance in one command, no Docker and no
  account. The previous first-run path required both before showing anything.
- **`haldir top`** — a live fleet console in the terminal, pure stdlib.
- **Monitoring console at `/admin/overview`** — which agent is doing what:
  sessions, spend against cap, live activity, flag reasons, and a revoke that
  cascades to subagents.
- **Usage-based billing.** One plan table (`haldir_tiers.py`) that every
  surface derives from, replacing five copies that had drifted to three
  different answers — $99/25 agents on the marketing site, $49/10 in the
  product. Caps bill rather than block, and the meter counts API calls.
- **Vault key rotation** without re-entering secrets.
- **An invariant suite** asserting the three core claims — spend cap, audit
  chain, vault binding — as properties under concurrency, not as examples.

### Security

- **A webhook URL could read local files and reach the internal network.**
  Outbound webhook delivery now rejects non-public destinations.
- **Cost was recorded at cent precision**, so x402 micropayments were logged
  as `$0.00`.

### Changed

- **CI now exercises the Postgres path.** It previously never did, on any
  pull request. Three things kept that invisible: stacked PRs matched no
  workflow at all (the trigger filtered on the PR's base branch, `main`); no
  job set `timeout-minutes`, so a hung run was cancelled by the next push and
  reported no verdict; and pytest's output capture meant the CI log held zero
  application log lines while an `AttributeError` printed for hours and the
  failure was attributed to database locks.
- **`haldir login` survives an environment with no TTY.**

## [0.3.1] — 2026-09-20

The "provable retention" release. Audit entries can now be pruned without
weakening the integrity claim, administrative actions join the same hash
chain as everything else, and the Postgres path runs in CI for the first time
— which immediately surfaced two Postgres-only bugs that had been shipped in
every prior release.

### Added

- **Retention windows**, with pruning that stays provable. Deleting history
  from an append-only log normally voids the evidence; the tree is rebuilt so
  the surviving entries still verify.
- **Administrative actions are audited** in the same hash chain as agent
  actions, so an operator's intervention is as accountable as the agent's.
- **Agent delegation hierarchy**, with spawn events recorded in the
  tamper-evident chain — revoking an orchestrator reaches the agents it
  created.

### Fixed

- **The compliance evidence digest changed just because you read it**, so two
  reads of identical evidence produced different digests.
- **Two Postgres-only bugs**, one of them silent, caught by the new CI job.
- **The published wheel could not be started.** Hatchling's `packages` is a
  shorthand that replaces `include`, so three top-level modules were dropped —
  the `haldir` console script, the `haldir-mcp` entry point, and the database
  layer both import. Nobody who ran `pip install haldir` could start the CLI.
- **The `haldir_*.py` glob** built a correct wheel locally and a wheel missing
  `haldir_logging.py` and `haldir_tracing.py` in CI. The module list is now
  explicit and asserted.
- **The cloud dashboard's data panels never loaded.**
- **CI had been red long enough to stop being read**: environment gaps, a
  hand-maintained test file list that omitted most of the suite, and a backlog
  of mypy errors.

### Changed

- **One MCP tool catalog on every surface** — stdio and HTTP had drifted.
- **Dependencies bounded**, with one manifest shared by dev and CI.
- **`.pyc` bytecode untracked**; committed bytecode had been shadowing source.
- **README and demo gallery rebuilt** around the tamper demo, with reproducible
  screenshot capture.

## [0.3.0] — 2026-04-19

The "production-grade platform" release. Eighteen feature commits fill in
every box a serious infra-tool review checks: middleware hygiene,
observability, declarative validation, machine-readable docs, performance
numbers, deployment hardening, schema migrations, retry-safe webhook
delivery, compliance export, Kubernetes probes, and a rebuilt CLI that
puts a face on all of it. Test suite grew from 79 → 310 cases.

### Added — Platform middleware

- **Idempotency-Key on every mutating POST** — Stripe-style retry safety
  for `/v1/sessions`, `/v1/audit`, `/v1/payments/authorize`,
  `/v1/approvals/*`, `/v1/webhooks`, `/v1/proxy/*`, `/v1/billing/checkout`.
  Tenant-scoped cache, SHA-256 body hash, 422 on key reuse with a
  different body.
- **Request-ID propagation** — inbound `X-Request-ID` echoed (length-capped
  at 64 chars) or generated; surfaces in every structured log line and
  every error envelope for end-to-end correlation.
- **Security headers** — HSTS, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy` set on
  every response.
- **MAX_CONTENT_LENGTH=1 MiB** with a JSON 413 error envelope.
- **Unified error envelope** `{error, code, request_id, ...}` across
  400/401/403/404/405/413/422/429/500.
- **Precise rate-limit headers** — `X-RateLimit-Limit/Remaining/Used/Reset/
  Reset-After/Resource` on every authed response, plus a parallel
  `X-RateLimit-Monthly-*` namespace for the subscription quota dimension.
  `Retry-After` (RFC 7231) on every 429.

### Added — Observability

- **Structured JSON logging** (`haldir_logging.py`) on stdlib `logging` with
  Flask request-context enrichment (request_id, tenant_id). Idempotent
  configure, env-driven level/format/silence.
- **In-process Prometheus metrics** (`haldir_metrics.py`) — Counter +
  Histogram + Registry, no external dep. Five default metrics:
  `haldir_http_requests_total`, `haldir_http_request_duration_seconds`,
  `haldir_rate_limit_exceeded_total`, `haldir_idempotency_hits_total`,
  `haldir_idempotency_mismatches_total`. `/metrics` endpoint gated by
  `HALDIR_METRICS_TOKEN` with constant-time compare.
- **Public status page** at `/status` (HTML) + `/v1/status` (JSON). Per-
  component health (api/database/billing/proxy), success rate from the
  metrics, p50/p95/p99 latency from the histogram.
- **`/livez` + `/readyz`** Kubernetes-grade probe split. Liveness is
  zero-I/O; readiness checks DB reachability, migration consistency, and
  encryption-key configuration. Returns 503 (not 200) when not ready so
  load balancers pull the pod without restarting it.

### Added — Declarative validation + auto-generated docs

- **`@validate_body`** decorator (`haldir_validation.py`) — declarative
  schema with type/required/default/min/max/maxlen/choices. `bool`
  deliberately rejected as `int`. Unknown fields silently dropped for
  forward compatibility. Schema stashed on the wrapper for introspection.
- **OpenAPI 3.1 generator** (`haldir_openapi.py`) walks the live Flask
  url_map and reads `@validate_body` schemas off view wrappers. Spec is
  the API by construction — never out of sync. Served at `/openapi.json`,
  rendered at `/swagger`.

### Added — Audit + compliance

- **Streaming audit export** (`/v1/audit/export?format=csv|jsonl`) with a
  signed integrity manifest. Batched LIMIT/OFFSET pagination so a million-
  row export doesn't OOM. JSONL embeds the manifest as the final record;
  a companion `/v1/audit/export/manifest` endpoint returns it standalone
  for CSV consumers.

### Added — Webhook delivery

- **Production-grade delivery** — every fire assigns a UUID `event_id`
  (sent as `X-Haldir-Webhook-Id` so receivers dedupe), stamps
  `X-Haldir-Delivery-Attempt`, and retries on 5xx + network errors with
  exponential backoff (1 s → 4 s, 3 attempts max).
- **`webhook_deliveries` table + `/v1/webhooks/deliveries` endpoint** —
  every attempt logged with status_code, response_excerpt (first 512 B),
  duration, and error. First load-bearing use of the migration runner.
- **`from haldir import verify_webhook_signature`** — SDK re-export so
  receiver code has one canonical import path for the security helper.

### Added — Tenant admin dashboard

- **`/v1/admin/overview`** — single-call dashboard returning tier, usage,
  sessions, vault, audit (with chain verification), webhooks (24h success
  rate), approvals, and embedded health. Pure SQL aggregates, no N+1.

### Added — Schema migrations

- **`haldir_migrate`** — forward-only, checksum-verified, dialect-aware
  migration runner. Discovers `migrations/NNN_*.sql`, applies what hasn't
  been recorded in `schema_migrations`, translates Postgres syntax for
  SQLite. Legacy bootstrap path adopts existing schemas as v1 without
  re-running migration bodies. CLI: `python -m haldir_migrate {up,status,
  verify}`.
- **`migrations/001_initial_schema.sql`** — baseline, every table Haldir
  ships with.
- **`migrations/002_webhook_deliveries.sql`** — the deliveries log table.
- **`HALDIR_AUTO_MIGRATE=1`** — opt-in boot hook; default-on in the new
  Dockerfile entrypoint.

### Added — DB layer

- **SQLite pragma tuning** — WAL + `synchronous=NORMAL` + 256 MiB mmap +
  in-memory temp store + 5 s busy timeout. Cuts the `GET /v1/sessions/:id`
  p99 from 349 ms to 172 ms under 32-way concurrent load.
- **Configurable Postgres pool** — `HALDIR_PG_POOL_MIN/MAX` env knobs
  (defaults 2 / 20).
- **Counter / Histogram `.snapshot()` accessors** so the status module can
  read metrics without reaching into private attributes.

### Added — Deployment + supply chain

- **Multi-stage Dockerfile** — builder compiles wheels, runtime is
  `python:3.12-slim` + libpq5 + curl + tini. Non-root uid 1000.
  `HEALTHCHECK` targets `/livez`. `/data` volume for SQLite.
- **`.dockerignore`** trims VCS, secrets, caches, tests, marketing
  artifacts.
- **`scripts/gen_sbom.py`** — CycloneDX 1.5 SBOM generator (stdlib-only,
  deterministic timestamp). Runs at Docker build time so
  `docker cp <container>:/app/sbom.json .` hands auditors the full dep
  list.

### Added — CLI

- **Seven new commands**: `haldir overview` (with `--watch` top-style
  redraw), `haldir status`, `haldir ready` (exits 0/1 for CI),
  `haldir audit export`, `haldir audit verify`,
  `haldir webhooks deliveries`, `haldir migrate up/status/verify`.
- **`--json` flag** on every new command so they compose into scripts.

### Added — Web

- **`/demo` page** — in-browser playground that hits the live API with a
  per-visitor sandbox tenant. Animated SVG quickstart at the top, four-
  button walk-through (mint key → create session → check permission → log
  audit) with live JSON responses.
- **Animated SVG quickstart** (`demo/quickstart.svg`) embedded in the
  README above the architecture diagram. 9 KB, regeneratable from
  `demo/gen_quickstart.py`.

### Added — Performance

- **Concurrent HTTP throughput benchmark** (`bench/bench_http.py`) —
  launches gunicorn locally, hits representative endpoints with N
  concurrent threads. Real numbers in the README: 1,247 RPS on
  `POST /v1/audit` at 25 ms p50, 41 ms p99 with the full middleware
  stack (auth, validation, idempotency, metrics, structured logging) in
  the path.

### Added — OpenTelemetry

- **Opt-in tracing** (`haldir_tracing.py`) — Gate/Vault/Watch operations
  emit spans when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. No-op otherwise.

### Changed

- **`User-Agent`** on outbound webhooks bumped to `Haldir/0.3.0`.
- **`/healthz`** now an alias for `/livez` (back-compat preserved).
- **OpenAPI default version** in the generator bumped to `0.3.0`.
- **`mypy` strict scope** expanded to 18 source files (was 9 in 0.2.2).
- **`README.md`** — performance table, demo SVG, CLI showcase, every new
  command documented.

### Verified

- 310 tests passing (was 79 in 0.2.2).
- mypy clean across 18 source files.
- Zero new runtime dependencies in the default `pip install haldir`.

## [0.2.2] — 2026-04-18

### Added

- **`autogen-haldir`** — governance integration for Microsoft's AutoGen (0.4+). `govern_tool(...)` wraps any AutoGen `BaseTool`/`FunctionTool` so every tool call is scope-checked (pre), cost-tracked + audit-logged (post), and halts with `HaldirPermissionError` on session revocation. Composes with AutoGen's async runtime at the `run_json` boundary. Completes the Big 4 of agent-framework integrations: LangChain, CrewAI, AutoGen, Vercel AI SDK.
- **Architecture diagram** (`docs/architecture.svg`) embedded in the README. Hand-coded SVG; no raster dependencies.
- **Framework-integrated examples** (`examples/langchain_agent.py`, `examples/crewai_crew.py`, `examples/vercel_ai_sdk.ts`) — end-to-end runnable demonstrations alongside the existing raw-HTTP examples.
- **Repository hygiene** — `.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/dependabot.yml` covering 7 ecosystems, `.github/CODEOWNERS`, `.github/FUNDING.yml`.
- **Proxy policy-engine tests** (`tests/test_proxy.py`) — 25 cases covering `block_tool`, `allow_list`, `deny_list`, `spend_limit`, `time_window`, multi-policy composition, and the `get_tools()` governance metadata shape. Brings the total test suite to 79 cases.
- **Comprehensive wiki** — 17 pages (Home, Getting Started, Architecture, Gate, Vault, Watch, Proxy, Self-Hosting, API Reference, MCP Server, Framework Integrations, Security, Roadmap, FAQ, Contributing, Sidebar, Footer) at [github.com/ExposureGuard/haldir/wiki](https://github.com/ExposureGuard/haldir/wiki).
- **SECURITY.md** — full disclosure policy with safe-harbor clause, scope, and 72-hour acknowledgment SLA.

### Changed

- **Package metadata** on both `haldir` (PyPI) and `haldir` (npm) — bumped to 0.2.x, richer descriptions reflecting AES-256-GCM + hash chain, comprehensive keywords (langchain, crewai, autogen, vercel-ai-sdk, aes-256-gcm, hash-chain, etc.), full trove classifiers (Topic :: Security :: Cryptography, Typing :: Typed), cross-linked URLs (Docs, Issues, Discussions, Changelog, Wiki, Self-Hosting guide, Security policy). Author migrated to `Sterling Ivey <sterling@haldir.xyz>`.
- **Landing page Schema.org JSON-LD** — includes `autogen-haldir` in the `hasPart` SDK list; updated description to mention all four frameworks.
- **llms.txt / llms-full.txt** — AutoGen added to the install list and the framework cheat-sheet section so any AI agent reading our discovery surface sees the full four-framework story.

## [0.2.1] — 2026-04-18

### Security — Vault cipher upgrade

- **Vault now uses AES-256-GCM** (was AES-128-CBC + HMAC-SHA256 via Fernet). 256-bit key, 96-bit random nonce per encryption, 128-bit authentication tag. Standard enterprise compliance checklist for data-at-rest.
- **Ciphertext is now bound to `(tenant_id, secret_name)` via AEAD additional authenticated data.** Swapping ciphertext between tenants or under a different secret name fails authentication — defense-in-depth against DB-tampering adversaries.
- **Key format:** 32 raw bytes or 44-char base64url string. Backward-compatible with existing env-var pattern; `Vault(encryption_key=...)` signature unchanged.
- **Breaking for existing secrets**: no migration path from Fernet ciphertexts. Existing self-hosted deployments must rotate secrets. The hosted service had no stored secrets from external users at the time of upgrade.

### Changed

- `.env.example`, `SELF_HOSTING.md`, `CONTRIBUTING.md`, `README.md`: key generation command updated to `base64.urlsafe_b64encode(os.urandom(32))`
- `haldir init` CLI command now generates AES-256-GCM keys
- Landing page, quickstart, MCP server tool description, HOW_IT_WORKS: AES-128 → AES-256-GCM

## [0.2.0] — 2026-04-18

### Added

- **Framework integrations** — native packages for the three dominant agent frameworks:
  - `langchain-haldir` — governance callbacks, tool wrappers, secrets helper
  - `crewai-haldir` — CrewAI `BaseTool` wrapping with scope enforcement + audit logging
  - `@haldir/ai-sdk` — Vercel AI SDK tool wrapping (TypeScript)
- **JS/TS SDK types** — `haldir` npm package now ships full TypeScript declarations (`index.d.ts`)
- **Hash-chained audit trail** — every Watch entry now cryptographically chains to the previous, producing tamper-evident logs
- **Cryptographic hash chaining** for Postgres deployments with deterministic float serialization
- **Pricing page** — `/pricing` route, Stripe subscription checkout, billing integration
- **Quickstart page** — interactive onboarding at `/quickstart` (mobile-friendly)
- **MCP discovery** — `/.well-known/mcp/mcp.json` for agent-protocol discovery
- **Demo API** — public `/v1/demo/key` endpoint so the landing page can run a live demo with zero signup
- **CLI tool** — `haldir` command-line interface for scripting
- **GitHub Action** — drop-in CI/CD governance for agent pipelines
- **Blog engine** — markdown rendering, SEO-friendly URLs, index page
- **SafeSkill security badge** — 89/100 Passes with Notes

### Changed

- **Landing page** — Proxy added as 4th product card; Pricing link in nav; Design Partners section
- **README** — Design partner CTA at top; GitHub Stars badge
- **Storage** — Postgres-first with persistent data across deploys (previously SQLite)
- **Rate limiter** — dedup logic and CORS hardening

### Fixed

- Hash chain verification across Postgres REAL/DOUBLE PRECISION timestamp precision mismatches
- Stripe checkout `customer_creation` parameter (not valid in subscription mode)
- Demo API key error handling and DB pool exhaustion under load
- Landing page AES-256 → AES-128 (reflects actual Fernet implementation)
- License consistency: MIT across `openapi.json`, `pyproject.toml`, `LICENSE`
- 7 critical P0 security issues prior to first external users (input validation, auth, rate limiting)

### Distribution

- `crewai-haldir` Python package: built + ready for PyPI publish
- `@haldir/ai-sdk` npm package: ESM + CJS + types, 4.9 KB tarball, ready for npm publish
- Submitted to `punkpeye/awesome-mcp-servers` (PR #5056)

## [0.1.0] — 2026-04-05

### Added

- **Gate** — scoped agent sessions with spend limits and TTL
- **Vault** — AES-encrypted secrets with per-session scope enforcement
- **Watch** — immutable audit log with anomaly flagging
- **Proxy** — MCP tool-call interception and policy enforcement
- **Approvals** — human-in-the-loop webhooks for high-risk actions
- **MCP server** — 10 tools exposed to any MCP-compatible AI client
- **REST API** — full OpenAPI 3.1 spec at `/openapi.json`
- **PyPI package** — `pip install haldir`
- **Smithery listing** — discoverable at `smithery.ai/server/haldir/haldir`

[0.3.0]: https://github.com/ExposureGuard/haldir/releases/tag/v0.3.0
[0.2.2]: https://github.com/ExposureGuard/haldir/releases/tag/v0.2.2
[0.2.1]: https://github.com/ExposureGuard/haldir/releases/tag/v0.2.1
[0.2.0]: https://github.com/ExposureGuard/haldir/releases/tag/v0.2.0
[0.1.0]: https://github.com/ExposureGuard/haldir/releases/tag/v0.1.0
