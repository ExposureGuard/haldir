# Security Policy

Haldir is governance infrastructure. Security issues are treated as the highest priority of any report.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.** Public disclosure before a fix is available puts Haldir users at risk.

Instead, please email:

- **[security@haldir.xyz](mailto:security@haldir.xyz)** (preferred)
- or [sterling@haldir.xyz](mailto:sterling@haldir.xyz)

Include as much of the following as possible:

- A description of the vulnerability and its impact
- Steps to reproduce (proof-of-concept code, HTTP requests, etc.)
- Any known workarounds or mitigations
- Whether you intend to publicly disclose, and your timeline

We acknowledge every report **within 72 hours**. For critical issues (active exploitation, RCE, privilege escalation, data exposure), we respond within 24 hours.

See also: [.well-known/security.txt](https://haldir.xyz/.well-known/security.txt) on the hosted service.

## Scope

In scope:

- The hosted service at **haldir.xyz**
- The core packages: `haldir` (Python), `haldir` (JavaScript), `langchain-haldir`, `crewai-haldir`, `@haldir/ai-sdk`
- Self-hosted Haldir deployed via the official `docker-compose.yml`
- The MCP server (stdio and HTTP transport)
- Authentication, session management (Gate), secret encryption (Vault), audit logging (Watch), and the Proxy enforcement layer

Out of scope:

- Vulnerabilities in third-party dependencies that have already been disclosed upstream (please report those to the upstream maintainers; we'll track updates)
- Rate-limiting / denial-of-service reports against the free tier of haldir.xyz
- Self-XSS
- Missing security headers without a working exploit
- Social engineering of Haldir employees or users
- Physical attacks against our infrastructure

## Our security posture

What Haldir does today:

- **Vault:** AES-256-GCM authenticated encryption with AAD binding (ciphertext is cryptographically bound to `(tenant_id, secret_name)`; swapping ciphertext between tenants or under a different name fails authentication)
- **Watch:** every audit entry is SHA-256 hash-chained to the previous entry; tamper-evident trail verifiable by any consumer
- **Gate:** short-lived scoped sessions with per-session spend caps; revocation is immediate and global
- **Proxy:** policy enforcement before any tool call reaches an upstream API
- **Transport:** TLS 1.3 for all hosted traffic (Cloudflare-fronted); stdio MCP for local agent transport
- **Secrets management:** encryption keys are injected at deploy time, never committed. Key rotation is supported.

We publish a CHANGELOG entry for every security-relevant release and tag them with a `security:` prefix in commit messages.

## Safe-harbor

Security researchers acting in good faith — that is, making every reasonable effort to avoid privacy violations, destruction of data, and interruption or degradation of service — will not face legal action from Haldir.

We do not currently run a paid bug bounty program, but we will:

- Acknowledge your report publicly in release notes (if you wish)
- Credit you in any CVE or public advisory we issue
- Coordinate disclosure timing with you

## Coordinated disclosure

Our default disclosure timeline:

1. **0–72 hours** — acknowledgment, triage, and severity classification
2. **3–14 days** — fix developed, tested, deployed to the hosted service
3. **14–30 days** — patched release tagged, CHANGELOG updated, public advisory published

We'll work with you on faster or slower timelines if the circumstances require it (e.g., widespread active exploitation, or a deeply embedded architectural issue).

## Hall of fame

Security researchers who have helped improve Haldir will be listed here.

*(This section is intentionally empty on day one. Help us fill it.)*
