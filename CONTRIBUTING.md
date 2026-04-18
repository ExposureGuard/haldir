# Contributing to Haldir

Thanks for your interest. Haldir is open-source because AI agent governance should be inspectable and portable, not locked behind a vendor's API. Every contribution — code, docs, bug reports, questions — makes the project better.

This guide gets you from "I want to help" to a merged PR in about 20 minutes.

---

## Quick start — local development

```bash
# 1. Fork the repo on GitHub, then clone your fork
git clone git@github.com:YOUR-USERNAME/haldir.git
cd haldir

# 2. Set up your environment
cp .env.example .env
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
# Paste the output into .env as HALDIR_ENCRYPTION_KEY

# 3. Spin up the stack (API + Postgres)
docker compose up -d

# 4. Verify
curl http://localhost:8000/health
```

Hot-reload during development:

```bash
# Local venv (no Docker) — good for iterating quickly on api.py
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=postgresql://haldir:haldir@localhost:5432/haldir
export HALDIR_ENCRYPTION_KEY='paste-your-key'
python api.py          # serves on :8000 with auto-reload
```

---

## What to work on

Good first contributions:

- **Bug reports with repros** — even without a fix, a reproducible bug report is massively helpful
- **Tests** — add test cases for edge cases we haven't covered
- **Docs polish** — typos, clarity, better examples
- **New framework integration** — AutoGen, LlamaIndex, Semantic Kernel, Pydantic AI, etc. (follow the `integrations/langchain-haldir/` pattern)
- **New MCP tools** — Haldir as an MCP server exposes 10 tools today; more is better
- **SDK ergonomics** — sync/async helpers, typed convenience methods

Check [open issues](https://github.com/ExposureGuard/haldir/issues) for items labelled `good first issue` or `help wanted`.

Planning something larger? Open a discussion first so we can align before you sink time into it: https://github.com/ExposureGuard/haldir/discussions

---

## Project layout

```
haldir/
├── api.py                REST API (Flask)
├── haldir_db.py          Database abstraction (Postgres + SQLite)
├── haldir_gate/          Gate module — sessions, scopes, spend caps
├── haldir_vault/         Vault module — encrypted secrets
├── haldir_watch/         Watch module — hash-chained audit trail
├── mcp_server.py         MCP server (stdio JSON-RPC)
├── sdk/                  Python SDK
├── sdk-js/               JavaScript/TypeScript SDK
├── integrations/         Framework integrations
│   ├── langchain-haldir/
│   ├── crewai-haldir/
│   └── vercel-ai-haldir/
├── landing/              haldir.xyz marketing page
└── blog/                 Markdown posts
```

---

## Code style

- **Python:** follow the existing style. Type hints on public APIs, f-strings for formatting, 4-space indent.
- **TypeScript:** existing code uses explicit types over inference for public APIs. No classes when a function works.
- **Commits:** one logical change per commit, short imperative message. "Add X" not "Added X."
- **Tests:** no formal requirement yet, but if you're fixing a bug, a regression test is strongly appreciated.

Run the smoke test before opening a PR:

```bash
# Tests live in tests/
python -m pytest tests/
```

For framework integrations, there's a live-API smoke test pattern — see `tmp/haldir_smoke_test.py` in recent commits for an example.

---

## Pull request checklist

Before opening a PR:

- [ ] Tests pass (`python -m pytest tests/`)
- [ ] Self-host still works (`docker compose up -d` + hit `/health`)
- [ ] Docs updated if you added a feature
- [ ] `CHANGELOG.md` entry under `## [Unreleased]`
- [ ] Commit messages are tidy (squash if you made experimental commits)

Then:

1. Push to your fork
2. Open a PR against `main`
3. Fill in the PR template (what / why / how tested)
4. Wait for review — we aim for first response within 48 hours

---

## Reporting security issues

**Do not open a public issue for security problems.** Email [security@haldir.xyz](mailto:security@haldir.xyz) instead. See `.well-known/security.txt` for the full policy.

---

## Code of conduct

Be kind. Assume good faith. Help others ship. That's it.

Offenders get one warning, then a block. We moderate proactively.

---

## License

By contributing, you agree that your contribution will be licensed under the [MIT License](LICENSE) — the same as the rest of the project. You retain copyright; you grant the project permission to use your contribution.

---

## Getting help

- **Chat:** https://github.com/ExposureGuard/haldir/discussions
- **Issues:** https://github.com/ExposureGuard/haldir/issues
- **Email:** sterling@haldir.xyz

Thanks for building Haldir with us.
