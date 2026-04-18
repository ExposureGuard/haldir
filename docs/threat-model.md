# Haldir Threat Model

This document enumerates the attacker profiles Haldir is designed to defend against, what we protect, what we explicitly do **not** protect, and the concrete mechanisms tying each defense to code and tests.

Scope: the hosted service at **haldir.xyz**, the `haldir` Python and JavaScript SDKs, all framework integrations (`langchain-haldir`, `crewai-haldir`, `autogen-haldir`, `llamaindex-haldir`, `@haldir/ai-sdk`), and self-hosted deployments using the official `docker-compose.yml`.

Out of scope: operating system hardening, network isolation at the host layer, physical security, social engineering of customers or staff.

---

## Assets

In decreasing order of sensitivity:

1. **The Vault encryption key** (`HALDIR_ENCRYPTION_KEY`). Compromise → every stored secret is recoverable by the attacker.
2. **Stored secrets** (API keys, credentials, tokens written via `POST /v1/secrets`).
3. **Active session tokens** (`ses_...` identifiers). Compromise → attacker can act as the agent until revocation.
4. **Audit trail integrity**. Tampering with past entries compromises compliance guarantees, post-mortem forensics, and regulator reporting.
5. **API keys** (`hld_...`). Tenant-scoped; compromise → full tenant access.
6. **Session budgets and scopes**. Compromise → agent escalates beyond authorized behavior.

---

## Attacker profiles

### A1 — Malicious end user of Haldir

Has a valid API key for tenant **A**, attempts to read/write tenant **B**'s data.

**Primary defense:** every DB query includes `WHERE tenant_id = ?`. The `tenant_id` is resolved from the API key at request time and never accepted from the request body or headers.

**Defense in depth:**
- Vault ciphertexts are AEAD-bound to `(tenant_id, secret_name)` — even if tenant B obtains tenant A's ciphertext, decryption fails (`InvalidTag`).
- All session lookups are tenant-filtered; passing another tenant's `session_id` returns `None`.

**Code:**
- `haldir_db.py` — every query helper includes tenant filtering
- `haldir_vault/vault.py` — `store_secret`/`get_secret` pass `aad=f"{tenant_id}:{name}".encode()`

**Tests:** `tests/test_vault.py::test_cross_tenant_ciphertext_swap_rejected`, `tests/test_gate.py::test_session_from_one_tenant_is_not_visible_to_another`.

---

### A2 — Prompt-injected or hijacked agent

Legitimate agent has been manipulated via prompt injection, malicious tool output, or unexpected LLM behavior. Attacker can make the agent issue any API call the agent's current session is authorized for.

**Primary defense:** scoped sessions. An agent created with `scopes=["read"]` cannot invoke `delete`, cannot spend, cannot retrieve secrets with `scope_required="write"`.

**Defense in depth:**
- Spend caps bound monetary damage even if the attacker gets the agent to invoke a payment-authorized tool.
- `client.revoke_session(sid)` is a global kill switch callable from any process holding the API key. The next tool call from the agent raises `HaldirPermissionError` regardless of what the LLM decides to do.
- Human-in-the-loop approval rules (`/v1/approvals/rules`) can gate specific operations behind explicit approval.
- The Proxy (`haldir_gate/proxy.py`) enforces policies before any upstream call — an agent trying to call a disallowed tool hits policy before it hits the upstream.

**Code:**
- `haldir_gate/gate.py` — `has_permission()`, `authorize_spend()`
- `haldir_gate/proxy.py::_enforce_policies`
- `haldir_gate/approvals.py`

**Tests:** `tests/test_gate.py` (scope matching, spend caps, revocation), `tests/test_proxy.py` (allow/deny lists, spend limits, time windows).

**What this does NOT protect against:**
- Actions the agent was authorized to take. If you create a session with `scopes=["spend", "execute"]`, a hijacked agent can spend up to the cap. Haldir limits blast radius; it does not decide whether an authorized action was wise.

---

### A3 — Read-only compromise of the backing database

Attacker obtains `SELECT *` on the Haldir Postgres instance (e.g., leaked backup, compromised read-replica credentials, disk theft, incorrect IAM grant).

**Primary defense:** **Vault stores ciphertext, never plaintext.** The attacker sees AES-256-GCM-encrypted blobs and cannot decrypt without the key (which lives in environment variables / a KMS, not the database).

**Defense in depth:**
- Nonces are 96 bits per ciphertext — attacker cannot correlate identical plaintexts across rows.
- Session IDs are 192 bits of entropy (`secrets.token_urlsafe(24)`). Reading session rows does not let the attacker guess future session IDs.

**Code:**
- `haldir_vault/vault.py` (AES-256-GCM, random nonce per call)
- `haldir_gate/gate.py::create_session` (`secrets.token_urlsafe(24)`)

**Tests:** `tests/test_vault.py::test_decrypt_with_wrong_key_raises_invalid_tag`, `tests/test_vault.py::test_store_twice_yields_different_ciphertexts`.

**What this does NOT protect against:**
- If the attacker also has the encryption key, every secret is compromised. Key management is the load-bearing control; treat `HALDIR_ENCRYPTION_KEY` like any other root secret.

---

### A4 — Read-write compromise of the backing database

Attacker can read and write any row in the Haldir Postgres instance. Can attempt to:

1. Silently modify audit entries (cover up what an agent did)
2. Swap ciphertext between tenants (steal secrets by relabelling)
3. Elevate a session's scopes or budget
4. Mark revoked sessions as valid

**Primary defenses:**

- **Audit tamper detection (hash chain).** Every `AuditEntry` contains `prev_hash` (SHA-256 of the previous entry for this tenant) and `entry_hash` (SHA-256 of this entry's fields including `prev_hash`). Modifying entry **N** requires:
  1. Recomputing N's `entry_hash` — but the stored value no longer matches
  2. Recomputing every subsequent entry's `prev_hash` — but the stored chain no longer matches the timeline
  
  An auditor holding *any* out-of-band-pinned recent `entry_hash` can verify the entire preceding chain. Tampering is therefore **detectable**, not preventable.

- **Vault AAD binding.** Ciphertext is AEAD-bound to `(tenant_id, secret_name)`. Moving a ciphertext row from tenant A to tenant B, or renaming `stripe_key` → `other_key`, breaks the AAD and decryption fails.

- **Session validity is DB-read each time.** `get_session` re-reads the `revoked` flag on every check; there is no server-side cache an attacker can poison.

**Mitigations, not preventions:**
- Session scope / budget fields are not cryptographically signed. A DB-write attacker can set `spend_limit = 1_000_000`. This is a documented gap; future work is on the [Roadmap](https://github.com/ExposureGuard/haldir/wiki/Roadmap) under "Policy learning + proof obligations."
- For maximum trust, anchor the latest `entry_hash` off-box — publish to a signed Git commit, a public blockchain, or send to the customer's auditor via authenticated email. This makes silent rewrites externally visible.

**Code:**
- `haldir_watch/watch.py::AuditEntry.compute_hash` — canonicalized payload, SHA-256
- `haldir_watch/watch.py::Watch.log_action` — chain linkage from the latest tenant entry

**Tests:** `tests/test_watch.py::test_tampering_a_middle_entry_breaks_the_chain`, `tests/test_watch.py::test_cross_tenant_ciphertext_swap_rejected`, `tests/test_vault.py::test_cross_name_ciphertext_swap_rejected`.

---

### A5 — Network eavesdropper

Attacker observes traffic between the Haldir SDK, the hosted API, and upstream MCP servers.

**Primary defense:** TLS 1.3 for all hosted traffic (enforced at Cloudflare). Haldir's MCP server supports both streamable-http (TLS) and stdio (local IPC, no network).

**Defense in depth:**
- API keys and session IDs are treated as bearer credentials. Request/response bodies are never compressed with attacker-influenced inputs (no CRIME/BREACH vector).
- Session IDs have 192-bit entropy — guessing is not feasible.

**What this does NOT protect against:**
- An attacker who MITMs the TLS connection (state actor with CA control, a customer misconfiguring their trust store).

---

### A6 — SDK/package supply-chain attack

Attacker publishes a malicious version of `haldir`, `langchain-haldir`, `crewai-haldir`, `autogen-haldir`, `llamaindex-haldir`, or `@haldir/ai-sdk` to PyPI/npm. User's agent installs the trojaned package and leaks session data or redirects calls.

**Primary defenses:**
- All SDK packages are signed to the same author (Sterling Ivey, `sterling@haldir.xyz`) with git commits matching the GitHub-verified account.
- Tagged releases on GitHub include SHA checksums; PyPI provenance (PEP 740) and npm provenance attestations are on the near-term [Roadmap](https://github.com/ExposureGuard/haldir/wiki/Roadmap).
- Users should pin to specific versions in `requirements.txt` / `package.json` — not use `latest`.

**What this does NOT protect against:**
- A compromise of the author's PyPI / npm publishing credentials. We use 2FA-enabled accounts and hardware-key-backed publish flows where possible.

---

### A7 — Compromised `HALDIR_ENCRYPTION_KEY`

Attacker obtains the symmetric key protecting the Vault.

**There is no secondary defense.** Every stored secret becomes decryptable with the key. This is intentional — a cipher that lets you partially recover data without the key is a bug.

**Mitigations that lower likelihood:**
- Generate the key via `os.urandom(32)` or equivalent; never reuse across environments.
- Store in AWS KMS / GCP Secret Manager / HashiCorp Vault / 1Password Business; inject at deploy time.
- Never commit to git. `.env.example` makes this explicit.
- Key-rotation job on the [Roadmap](https://github.com/ExposureGuard/haldir/wiki/Roadmap) — the current workflow (decrypt-and-reencrypt every secret) is documented in [SELF_HOSTING.md](../SELF_HOSTING.md).

---

### A8 — Side-channel attacks against the Haldir process

Memory scraping, speculative execution leaks, timing attacks.

**Out of scope.** Haldir is a userspace governance library; it does not claim secure-enclave guarantees. If your threat model includes nation-state adversaries with host-level access, run Haldir inside a confidential-computing environment (AWS Nitro Enclaves, GCP Confidential VMs, Intel SGX). The architecture supports this (API is stateless, all persistent state is in Postgres), but hardening is the operator's responsibility.

---

### A9 — Intentional exfiltration by authorized code

The user's own code, after calling `.get_secret_value()`, can do anything with the plaintext.

**This is outside Haldir's trust boundary by design.** Once your code has a plaintext credential, what your code does with it is your responsibility. Haldir makes accidental exposure (logs, prompts, tracebacks) hard via the `SecretStr` / `Secret` wrapper types. It does not prevent intentional misuse.

---

## Non-goals

The following are deliberately **not** in Haldir's threat model:

- **Prompt injection detection.** That's Guardrails AI / Lakera / Rebuff's job. Haldir enforces what happens *after* the LLM decides; it doesn't validate the LLM's input.
- **LLM output validation.** Same reasoning. An agent outputting hallucinated citations is not a Haldir problem.
- **Model-weight tampering.** Haldir is model-agnostic and doesn't inspect or sign models.
- **Customer identity provider integration.** Federated SSO is on the [Roadmap](https://github.com/ExposureGuard/haldir/wiki/Roadmap); for now, `hld_...` API keys are the authentication unit.

---

## Compliance posture

| Standard | Status |
|---|---|
| SOC 2 Type I | In progress — target Q3 2026 |
| SOC 2 Type II | 6 months after Type I |
| HIPAA BAA | Available on Enterprise plan (in discussion with early design partners) |
| ISO 27001 | Post-SOC 2 |
| FedRAMP | Conditional on government customer demand |
| GDPR | Supported via self-host in any region |

---

## Reporting

Found a gap in this threat model, or a real vulnerability? Email [security@haldir.xyz](mailto:security@haldir.xyz) or see [SECURITY.md](../SECURITY.md) for the full disclosure process and safe-harbor clause. Credit on published advisories if desired.

---

## Related

- [SECURITY.md](../SECURITY.md) — disclosure policy, SLA, safe harbor
- [Vault — wiki](https://github.com/ExposureGuard/haldir/wiki/Vault) — detailed cipher walkthrough
- [Watch — wiki](https://github.com/ExposureGuard/haldir/wiki/Watch) — hash chain construction + verification
- [.well-known/security.txt](https://haldir.xyz/.well-known/security.txt) — machine-readable contact info
