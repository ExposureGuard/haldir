# Changelog

All notable changes to Haldir are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

[0.2.2]: https://github.com/ExposureGuard/haldir/releases/tag/v0.2.2
[0.2.1]: https://github.com/ExposureGuard/haldir/releases/tag/v0.2.1
[0.2.0]: https://github.com/ExposureGuard/haldir/releases/tag/v0.2.0
[0.1.0]: https://github.com/ExposureGuard/haldir/releases/tag/v0.1.0
