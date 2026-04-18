# Changelog

All notable changes to Haldir are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

[0.2.1]: https://github.com/ExposureGuard/haldir/releases/tag/v0.2.1
[0.2.0]: https://github.com/ExposureGuard/haldir/releases/tag/v0.2.0
[0.1.0]: https://github.com/ExposureGuard/haldir/releases/tag/v0.1.0
