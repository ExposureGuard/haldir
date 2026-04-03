# Show HN: Haldir – Identity, secrets, and audit for AI agents (MCP-native)

AI agents are about to interact with the real world — browsing, paying, calling APIs, sending emails. But right now there's no standard way to give an agent an identity, manage its credentials, limit its spending, or audit what it did.

I built Haldir to fix that. It's three things:

**Gate** — Scoped sessions for agents. Permissions, spend limits, and TTL enforced on every tool call. No session, no access.

**Vault** — Encrypted secrets that agents never see directly. API keys, credentials, payment authorization with per-session budgets. The agent asks for access; Vault decides.

**Watch** — Immutable audit log for every action. Anomaly detection, cost tracking, compliance exports. The layer enterprises need before they'll deploy agents.

Everything is exposed as MCP tools (Model Context Protocol) so it works with Claude, GPT, Cursor, Windsurf, or any MCP-compatible AI. Also has a REST API.

Live demo on the landing page (the terminal types out a real workflow): https://haldir.xyz

API is live: https://haldir.xyz/v1

Tech: Python, Flask, SQLite (WAL mode), Fernet encryption, MCP SDK.

I built this because I was shipping an MCP server for my other project (ExposureGuard, domain security scanning) and realized every agent builder is solving identity/secrets/audit independently. There's no middleware layer. Haldir is that layer.

Looking for feedback from anyone building with AI agents. What am I missing? What would make you use this?
