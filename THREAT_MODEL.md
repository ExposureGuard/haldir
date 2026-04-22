# Haldir Threat Model

**Version:** 1.0 (2026-04-20)
**Audience:** Security engineers, auditors, enterprise procurement, VCs running technical diligence.
**Format:** STRIDE per component + named adversary scenarios + honest residual-risk
declarations.

This document is meant to be **boring on purpose** — no marketing language, no hand-waving.
If a claim isn't true, it doesn't appear. If a defence has a hole, the hole is named.

---

## 1. System overview

Haldir is the governance layer between AI agents and the tools they call. Five primitives:

| Primitive | What it does |
|---|---|
| **Gate** | Mints scoped agent sessions with permissions, spend limits, and TTLs. Every tool call is gated. |
| **Vault** | Stores AES-256-GCM-encrypted secrets with AAD-bound tenant isolation. Agents request secrets; raw values are never returned outside an authorized session scope. |
| **Watch** | Records every action to a SHA-256 hash-chained, RFC 6962 Merkle-tree-covered audit log. Inclusion + consistency proofs verify offline. STHs are Ed25519-signed and self-published to an anti-equivocation log. |
| **Proxy** | Forwards MCP tool calls to upstream servers after policy evaluation. |
| **x402** | Optional pay-per-request surface. Three priced endpoints route through a Coinbase-compatible facilitator for verify + settle. |

Public site: <https://haldir.xyz>. Source: <https://github.com/ExposureGuard/haldir>. PyPI: `haldir`. MCP stdio server: `haldir mcp serve`.

### Trust boundaries

```
                    ┌──────────────────────────────────────────────────┐
                    │  HALDIR PROCESS (single trust zone v1)           │
   ┌──────────┐     │                                                  │     ┌──────────┐
   │ AI Agent │ ──▶ │  Flask routes ─▶ Gate / Vault / Watch / Proxy ─▶ │ ──▶ │ Upstream │
   └──────────┘     │      │                                           │     │   tools  │
                    │      ▼                                           │     └──────────┘
                    │  SQLite / Postgres                               │
                    └─────────────────┬────────────────────────────────┘
                                      │
                ┌─────────────────────┼──────────────────────┐
                ▼                     ▼                      ▼
        ┌───────────────┐    ┌────────────────┐     ┌────────────────┐
        │ Auditor       │    │ x402           │     │ External       │
        │ (RO via API)  │    │ facilitator    │     │ mirror (TBD)   │
        └───────────────┘    └────────────────┘     └────────────────┘
```

The **single Haldir process** is the dominant trust boundary in v1. Mitigations for compromise of that boundary (external transparency mirror, BYOK signing keys) are tracked in §10.

### Data classification

| Class | Examples | Storage |
|---|---|---|
| **Tier 0 — secrets** | Vault values, Ed25519 signing key material | AES-256-GCM at rest; never logged |
| **Tier 1 — tenant-private** | Audit entries, evidence packs, sessions, API keys | Encrypted at rest where the cipher is configured; tenant-scoped on every query |
| **Tier 2 — operator** | Server logs, request metadata | Standard logging; PII-aware redaction |
| **Tier 3 — public** | STHs, public keys (JWKS), discovery manifests | Anyone can read |

---

## 2. Assets

What an attacker would want and why.

| Asset | Attacker goal | Impact if lost |
|---|---|---|
| Vault secrets (API keys, tokens, credentials) | Lateral movement into tenant's third-party services | Direct loss of customer's downstream systems |
| Audit log integrity | Hide a malicious action that happened | Destroys the entire compliance + tamper-evidence story |
| STH signing key | Forge tree heads after rewriting the log | Allows undetectable historical rewrite |
| API keys | Impersonate a tenant; mint sub-keys; exfiltrate | Full tenant compromise |
| Cross-tenant data | Read/write another tenant's anything | Multi-tenancy break — class-action risk |
| Webhook secrets | Forge events to downstream systems | Triggers automated actions in tenant's ops tools |
| Idempotency cache | Replay a paid action; double-charge | Customer-visible billing inconsistency |
| x402 facilitator trust | Accept fake settlements; ship resources without payment | Direct revenue theft |

---

## 3. Adversaries

Named, scoped, with a goal. No "advanced persistent threat" hand-waving.

### A1. Curious customer
**Profile:** Legitimate Haldir tenant with valid API key and full scope vocabulary on their own account.
**Goal:** Read another tenant's audit log, vault, or evidence pack.
**Capabilities:** Anything an authenticated user can do via the public API.

### A2. Malicious agent
**Profile:** AI agent under Haldir governance whose prompts have been hijacked or whose model misbehaves.
**Goal:** Drain the session's spend limit, exfiltrate secrets it has scope for, or invoke unscoped tools.
**Capabilities:** Anything the session it holds is authorized for.

### A3. Compromised wallet
**Profile:** External party who has stolen a Haldir API key (e.g. via repo leak, env-var exfiltration on customer side).
**Goal:** Use the stolen key for as long as possible without detection.
**Capabilities:** Full scope of the stolen key until revocation.

### A4. Insider with DB access
**Profile:** Haldir operator (Sterling, future engineers) with direct read/write to the Postgres backing store.
**Goal:** Rewrite a specific past audit entry (e.g. cover up a payment, hide a flagged action) without auditors detecting.
**Capabilities:** Anything that bypasses the application layer.

### A5. Network adversary
**Profile:** On-path attacker between an agent and Haldir, or between Haldir and a webhook receiver / x402 facilitator / upstream MCP server.
**Goal:** Intercept secrets in transit, modify webhook payloads, replay payments, MITM facilitator responses.
**Capabilities:** Standard active network capabilities (downgrade, replay, modify) where TLS isn't enforced.

### A6. Compromised facilitator
**Profile:** The x402 facilitator (default `https://x402.org/facilitator` or CDP) lies about a settlement.
**Goal:** Cause Haldir to ship a paid resource without an actual on-chain transfer happening.
**Capabilities:** Returns crafted `verify`/`settle` responses.

### A7. State-level discovery agent
**Profile:** Hostile party scraping `/.well-known/x402.json`, the MCP server card, llms.txt, etc.
**Goal:** Enumerate tenants, harvest exposed metadata, identify pivot points.
**Capabilities:** Anything an unauthenticated HTTP client can do.

---

## 4. STRIDE per component

### 4.1 Gate (sessions + scopes)

| Threat | Mitigation | Residual |
|---|---|---|
| **S** Session-id forgery | Session IDs are 256-bit URL-safe random (`secrets.token_urlsafe(32)`). Verified server-side against the `sessions` table on every request. | Negligible at 2^256 entropy. |
| **T** Scope escalation by editing session in DB | Application layer never re-reads scopes from request input; scopes are pinned at session-creation time. A6 (DB-level adversary) bypasses this — see §5. | DB-write attacker can rewrite session.scopes silently. Mitigated long-term by §10.3 (tamper-evident DB). |
| **R** Agent denies having taken an action | Watch logs every action with `session_id` + `agent_id`; logs are hash-chained + Merkle-covered. | Repudiation requires forging both chain head AND the published STH log — see §4.3. |
| **I** Session enumeration via timing | Constant-time session-not-found vs. wrong-tenant lookups; both return 404 with identical body. | Verified in `test_gate.py`. |
| **D** Session-creation flood exhausts agent quota | Per-tier `TIER_LIMITS["agents"]` cap, enforced before INSERT. Free tier capped at 1 agent. | A tenant-internal attacker can DoS sessions for the rest of the tenant's agents until the cap resets. |
| **E** Privilege escalation via scope-inheritance | Sub-keys minted via `POST /v1/keys` inherit `tenant_id` only — scopes must be explicitly re-listed and are validated against `SCOPE_VOCABULARY`. | Validated by `tests/test_keys_admin.py` + `tests/test_scopes.py`. |

### 4.2 Vault (secrets)

| Threat | Mitigation | Residual |
|---|---|---|
| **S** Secret read by another session | Each `get_secret` checks the requesting session's scopes against `secret.scope_required` before decryption. | Validated by `test_vault.py`. |
| **T** Cross-tenant ciphertext substitution | Each ciphertext is bound to `(tenant_id, secret_name)` via AAD in AES-256-GCM. A swapped ciphertext fails the AEAD tag check. | Validated by `test_vault_properties.py` (Hypothesis). |
| **R** Tenant denies storing a secret | `secrets` table carries `created_at` + tenant. Vault writes are also reflected in the audit log. | Standard. |
| **I** Vault key disclosure | Vault key is loaded from `HALDIR_ENCRYPTION_KEY`; if absent, an ephemeral key is generated and a WARNING is logged ("secrets will be lost on restart"). | If the key is leaked, every ciphertext for that key generation is decryptable. Mitigation: BYOK roadmap (§10.4). |
| **D** Decryption-error enumeration | Constant-time AEAD failure path; same 404 shape as not-found. | Validated by `test_vault_properties.py`. |
| **E** Privilege escalation via session/scope mismatch | Secret reads always require BOTH `vault:read` API-key scope AND a session whose scopes include the secret's `scope_required`. | Two-factor model is intentional. |

### 4.3 Watch (audit log)

| Threat | Mitigation | Residual |
|---|---|---|
| **S** Forged audit entry from outside the tenant | All `POST /v1/audit` calls require `audit:write` scope on a tenant-scoped key. Entries are written with `tenant_id` from the authenticated key, not from the request body. | Standard. |
| **T** Silent rewrite of a single past entry | SHA-256 hash chain: each entry binds to the previous entry's hash. A rewrite breaks the chain → `verify_chain` returns `verified: false` and identifies `first_break`. | Validated by `test_watch.py`. |
| **T** Coordinated rewrite of all entries + STH | RFC 6962 Merkle tree over the chain produces a fresh root per write. Auditor pinning a previous STH detects rewrite via consistency proof. Self-published STH log (`/v1/audit/sth-log`) catches equivocation: the recorded row at the auditor's pinned tree_size has a fixed root_hash, queryable forever. | Defeated only if the SAME process that rewrites the audit log ALSO rewrites the sth_log table AND every external mirror — see §10.3 for the external mirror roadmap. |
| **T** Server signs different STHs for different auditors at the same tree size | First observation of each (tenant, tree_size) is canonical via DB primary key. `/v1/audit/sth-log/verify` returns `reason=equivocation` with both root values surfaced when a pinned root differs from the recorded root. | Single self-published log only catches DELAYED equivocation; live equivocation requires external monitor gossip (§10.3). |
| **R** Tenant denies an entry was ever logged | Every entry has a UUID `entry_id` and is included in the next computed Merkle root. Inclusion proof is offline-verifiable against any STH whose tree_size ≥ the entry's leaf index. | Strong. |
| **I** Reading another tenant's audit trail | Every audit-related query carries `WHERE tenant_id = ?`. Verified across `test_audit_export`, `test_compliance`, `test_audit_tree`. | Standard. |
| **D** Log-write amplification | `audit_log` writes are a single INSERT per request. No client can force multi-row writes per request. | Not a meaningful DoS vector. |
| **E** Privilege escalation by injecting flagged-status | `flagged` is set by Watch's anomaly engine, not the writer. Clients cannot self-flag. | Standard. |

### 4.4 Proxy (MCP forwarding)

| Threat | Mitigation | Residual |
|---|---|---|
| **S** Upstream impersonation | Upstreams are registered per-tenant with explicit URL; no DNS rebinding possible at insertion time. | If an attacker can MITM the upstream URL post-registration, they can impersonate it. Mitigation: upstream identity pinning is on the roadmap; today, operators should use HTTPS upstreams only. |
| **T** Tool-result tampering on the wire | Upstream responses are sent through to the client without modification by Haldir. TLS to upstream is the only protection. | Standard MITM risk if upstream is HTTP. |
| **R** "Did Haldir actually call upstream?" | Every proxied call writes an audit_log entry with the tool + arguments + result hash. | Standard. |
| **I** Disclosure of registered upstreams to other tenants | Upstreams are tenant-scoped on every read. | Standard. |
| **D** Upstream slowdowns block Haldir threads | Proxy uses async + per-call timeouts. Honored timeout default = 30s. | A flood of slow upstreams can degrade Haldir if `gunicorn` worker count is undersized. Operational config issue. |
| **E** Policy bypass via crafted arguments | Policy evaluation uses an explicit tool/action allow-list per session scope. Argument sanitization is the upstream's responsibility. | Standard. |

### 4.5 x402 (pay-per-request)

| Threat | Mitigation | Residual |
|---|---|---|
| **S** Forged `PAYMENT-SIGNATURE` header | Header parsing validates structure + `x402Version=2` + non-empty `accepted` + `payload`. Cryptographic verification is delegated to the facilitator's `/verify` endpoint. | Trust boundary on the facilitator — see A6. |
| **T** Replay of a settled payment | EIP-3009 nonces are 32-byte random; the facilitator enforces single-use on-chain. Idempotency at the Haldir layer is sequence-based (audit-log row per settlement). | Single-use enforcement lives at the facilitator + on-chain — Haldir trusts this. |
| **R** Buyer denies they paid | Every settled payment writes an `audit_log` entry with the on-chain tx hash. The Merkle tree covers it. | Standard. |
| **I** Wallet enumeration via 402 responses | The 402 response always carries the SAME `payTo` address (the configured Haldir wallet). Buyers don't see other tenants. | Standard. |
| **D** 402 burst with no payment | Each 402 is cheap (no facilitator call until a `PAYMENT-SIGNATURE` is sent). Rate limits apply. | Standard. |
| **E** Privilege escalation via test-mode | `HALDIR_X402_TEST_MODE=1` accepts ANY structurally-valid PaymentPayload without facilitator verification. The module logs a WARNING on every flag-on, surfaces the flag in `/v1/x402/manifest`, and is excluded from prod by Railway env-var policy. | If an operator sets test mode in prod, attackers get free resources. Operational risk; mitigated by loud logging + manifest disclosure. |

### 4.6 STH log (anti-equivocation)

| Threat | Mitigation | Residual |
|---|---|---|
| **S** Forged sth_log row | Writes go through `haldir_sth_log.record()` which only writes the in-process STH that just got signed. No external write path. | Standard. |
| **T** Silent overwrite of an old STH row | `(tenant_id, tree_size)` PK + `INSERT OR IGNORE` semantics: the FIRST observation wins, attempts to overwrite are no-ops at the SQL layer. | Defeated by A4 (DB-level adversary): they can directly UPDATE the row. Mitigation: external mirror in §10.3. |
| **R** "Did Haldir record this STH?" | `/v1/audit/sth-log` returns the full history. Any auditor can demand it. | Standard. |
| **I** Cross-tenant STH leakage | Every list/verify is scoped on `tenant_id`. | Validated by `test_sth_log.py`. |
| **D** Log-write floods | Idempotent on `(tenant_id, tree_size)`; cannot be amplified beyond the rate of audit-log growth. | Bounded by audit-log throughput. |
| **E** Equivocation that the verifier can't surface | `verify_against_pinned` returns `reason=equivocation` with BOTH root values. Auditor publishes the pair; cryptographic proof is in their hands. | Strong. |

---

## 5. Named scenarios

### S1. Insider rewrites a single audit entry to hide an over-budget refund

A4 has Postgres root. They `UPDATE audit_log SET cost_usd = 0.50 WHERE entry_id = 'ent-XYZ'`.

**Detection path:**
1. The hash-chain entry_hash for `ent-XYZ` was computed over `cost_usd=12500` originally.
2. Recomputing the chain via `/v1/audit/verify` produces a different chain head than what's stored on `ent-XYZ.entry_hash` — the chain breaks at the first downstream entry.
3. `verify_chain` returns `{verified: false, first_break: <entry after XYZ>}`.

**To suppress detection,** A4 must also recompute every downstream entry_hash, the current Merkle root, and re-sign the STH. Even then, an auditor with a previously-pinned STH for any tree_size > XYZ's leaf-index detects the rewrite via consistency-proof failure.

**To suppress detection THEN,** A4 must also overwrite the corresponding row in `sth_log` for the auditor's pinned tree_size — but the auditor downloaded their pin offline. Their local copy doesn't change. `/v1/audit/sth-log/verify` returns `reason=equivocation`.

**Residual:** A4 needs to (a) own the DB write path, (b) own every external mirror, AND (c) compromise every auditor's local pinned STH simultaneously. This is the boundary where §10.3 (external mirror) closes the loop.

### S2. Compromised API key drains a tenant's spend across all sessions

A3 has a tenant's `hld_xxx` key with `audit:write` + `payments:write` scope.

**Detection path:**
1. Anomalous spend triggers Watch's anomaly rules (default: spend rate > 5×stddev over rolling 1h window). A `payment.spend_anomaly` webhook fires.
2. The tenant revokes the key via admin endpoint or CLI; revocation is immediate (next request returns 401).

**Mitigation:** key rotation on schedule + monitoring webhook subscriptions. Documented in `docs/operations.md`.

**Residual:** between key compromise and detection, A3 can spend up to per-session limits across all the tenant's sessions. This is fundamentally a credential-hygiene problem; Haldir caps the blast radius via per-session spend limits but cannot prevent the initial damage.

### S3. Network adversary modifies a webhook payload to fire a fake approval

A5 sits between Haldir and the tenant's webhook receiver.

**Mitigation:** every webhook body is signed with an HMAC-SHA256 over the canonical `(timestamp, body)` tuple. The receiver verifies via `haldir.verify_webhook_signature(...)` and rejects on bad signature OR a timestamp older than 5 minutes (replay window).

**Residual:** if A5 has the webhook secret (e.g. via repo leak on the receiver side), they can forge. Mitigation: secret rotation via `POST /v1/webhooks/<id>/rotate-secret` which gives a 24h overlap window.

### S4. x402 facilitator returns a fake settlement

A6 lies: `success: true, transaction: <fake tx hash>`.

**Mitigation v1:** Haldir trusts the facilitator. The facilitator URL is configurable via `HALDIR_X402_FACILITATOR_URL`; tenants choosing a self-run facilitator extend their trust to themselves only.

**Mitigation v2 (roadmap):** verify the tx hash on-chain via a separate RPC call before unlocking the resource. ~2x latency cost.

**Residual:** in v1, a malicious facilitator can grant resources without on-chain payment. The blast radius is bounded by the price per call ($0.001–$0.10 for current Haldir endpoints).

### S5. Multi-tenancy break via SQL injection

Every query is parameterized via the DBAPI cursor. No string-concatenated SQL anywhere — verified by grep + reviewed in `test_db.py`.

**Mitigation:** parameterized queries everywhere; a future static-analysis CI step (bandit) will catch any regression.

**Residual:** a pre-existing SQL-injection vulnerability would be a P0 incident. None identified at this version.

---

## 6. What we do not defend

Boundaries we explicitly accept.

| Out of scope | Why |
|---|---|
| Compromise of the Haldir process itself | A v1 server has no enclave / TEE. If the Haldir process is rooted, every defence in this document fails. Mitigation: external mirror (§10.3) catches DB rewrites; BYOK signing keys (§10.4) prevent forging STHs even from inside the process. |
| Customer's own credential hygiene | If a customer leaks `HALDIR_API_KEY` to GitHub, that's their incident — Haldir ships rotation tooling but cannot prevent leaks. |
| Browser-side XSS on customer apps | Haldir is API-first; HTML surfaces (`/compliance`, `/demo/tamper`) are noindex + no JS that consumes user input. |
| Side-channel attacks on AES-256-GCM | Standard NIST primitive; cryptography library handles it. Out of scope to re-implement. |
| Quantum attacks on Ed25519 | The post-quantum migration story is a 5-10 year horizon. When NIST PQC standards solidify, STH signing keys become hybrid Ed25519 + ML-DSA. Tracked as a future work item. |
| DDoS at the infrastructure layer | Cloudflare is the front-edge; Haldir's app-layer rate limits are a second line. We do not claim DDoS mitigation as a Haldir feature. |

---

## 7. Cryptographic primitives

| Surface | Primitive | Rationale |
|---|---|---|
| Vault encryption | AES-256-GCM with AAD = `tenant_id \| secret_name` | NIST-approved AEAD; AAD prevents cross-tenant ciphertext substitution |
| Audit hash chain | SHA-256 over canonical entry payload + prev_hash | Per-entry tamper detection without external state |
| Audit Merkle tree | RFC 6962 with SHA-256 leaf and node hashing | Same primitive Certificate Transparency uses for WebPKI; auditor-verifiable inclusion + consistency proofs |
| STH signing | Ed25519 (preferred) or HMAC-SHA256 (back-compat) | Asymmetric path lets verifiers prove without holding a forgery-capable key |
| Webhook signing | HMAC-SHA256 over `(timestamp, body)` with 5-min replay window | Symmetric; receivers hold the same key Haldir signs with |
| API keys | 256-bit `secrets.token_urlsafe`; SHA-256 hashed at rest | Key prefix `hld_` for visual identification; no raw keys in any DB |
| Idempotency | UUIDv4 keys + canonical-input hash | Prevents replay of mutating endpoints |

All key material is loaded from environment variables; ephemeral generation happens only in dev and produces a loud WARNING log.

---

## 8. Audit + verification interfaces

These are the surfaces an auditor uses to verify Haldir's claims without trusting Haldir.

| Endpoint | What it proves |
|---|---|
| `GET /v1/audit/verify` | Hash chain integrity end-to-end |
| `GET /v1/audit/tree-head` | Current Signed Tree Head |
| `GET /v1/audit/inclusion-proof/<entry_id>` | A specific entry is in the current tree |
| `GET /v1/audit/consistency-proof?first=N&second=M` | Tree-N is a prefix of tree-M (no historical rewrite) |
| `GET /v1/audit/sth-log` | Full history of every STH ever issued |
| `GET /v1/audit/sth-log/verify?pinned_size=N&pinned_root=H` | Anti-equivocation: pinned STH still matches |
| `GET /.well-known/jwks.json` | Public key for offline STH verification |
| `GET /v1/compliance/evidence` | Signed audit-prep evidence pack |
| `GET /v1/compliance/evidence/manifest` | Just the signature block (auditor re-verify) |

Same primitives ship as Python SDK functions: `haldir.verify_inclusion_proof`, `haldir.verify_consistency_proof`, `haldir.verify_sth`. Customers verify offline against the pinned JWKS public key with zero trust in the Haldir server.

---

## 9. Disclosure

Found something? Report:

- **Email:** `sterling@getexposureguard.com`
- **`.well-known`:** `https://haldir.xyz/.well-known/security.txt`
- **PGP / signed disclosure:** request via the email above.

We acknowledge within 48 hours, fix-or-mitigate within 30 days for HIGH+, and credit reporters publicly with permission.

We will **not**:
- Take legal action against good-faith research.
- Require coordinated-disclosure embargoes longer than 90 days.

We **will**:
- Publish a write-up after the fix lands, including reproduction steps and the affected versions.
- Issue a CVE for any vulnerability with cross-tenant impact.

---

## 10. Roadmap

What's not yet built. Documented honestly.

### 10.1 Per-tenant scope-of-secret enforcement at decryption time
Today, `vault_get_secret` checks scope at the API layer. A future change moves the scope check into the AEAD AAD itself, so a stolen ciphertext can only be decrypted by a session whose scopes match — defence in depth.

### 10.2 Constant-time across-the-board
Several endpoints (session lookup, secret lookup) are constant-time. Some admin endpoints aren't. A hardening pass + property-based timing tests is on the bench.

### 10.3 External transparency mirror
Today, `sth_log` is single-DB. A coordinated DB-write attacker can rewrite both `audit_log` AND `sth_log` simultaneously. Mitigation: mirror every STH to (a) Sigstore Rekor as an attestation, (b) a file the operator rotates to a WORM bucket, or (c) an HTTP archiver. Either anchor makes silent rewriting infeasible — even DB compromise can't reach the external log.

**Status:** **SHIPPED** (`haldir_transparency_mirror.py`). Three backends implemented: `file:<path>`, `http://...`, `rekor[:url]`. Every STH is mirrored on publish; receipts live in `sth_mirror_receipts` + exposed at `GET /v1/audit/sth-log/mirror/receipts`. The Rekor backend sends a `hashedrekord` entry with the canonical-STH SHA-256 digest + Ed25519 public-key PEM + signature — exact shape Rekor accepts for arbitrary attestations. Opt-in via `HALDIR_TRANSPARENCY_MIRROR`; default is off so nothing changes for operators who don't configure it. A coordinated attacker now has to compromise Haldir's DB **plus** every mirror backend **plus** every auditor's saved receipt, simultaneously. That's an attack cost increase of multiple orders of magnitude.

**10.3b — Rekor receipt verification** (SHIPPED, `haldir_rekor_verify.py`):

The v1 mirror trusted that the facilitator's HTTP response was genuine. A lying facilitator could hand us a fabricated UUID + logIndex and we'd persist it. The verifier now cryptographically validates every stored Rekor receipt against Rekor's own published public key before trusting it:

  1. **RFC 6962 inclusion proof.** We reconstruct the leaf hash from the entry body, walk the audit path, and check the resulting root matches the `rootHash` in the receipt. Delegates to `haldir_merkle.verify_inclusion` — the same property-tested verifier that validates Haldir's own tree (one less primitive the auditor has to trust).
  2. **SignedEntryTimestamp (SET) signature.** Rekor signs over the canonical JSON of `{body, integratedTime, logID, logIndex}` with ECDSA-P-256. We fetch Rekor's public key live from `/api/v1/log/publicKey` and verify the signature.
  3. **logID fingerprint.** Rekor's logID is `SHA-256(DER-encoded pubkey)`. If the receipt claims a different logID than the key we fetched, the receipt was issued by a different Rekor instance (or the mirror is lying about which log it used). Checked explicitly.

Endpoint: `GET /v1/audit/sth-log/mirror/receipts/<receipt_id>/verify` returns `{verified, reason, checks, pubkey_fingerprint}`. SDK re-export: `haldir.verify_rekor_receipt(receipt)`. 25 tests cover 11 parametrized tree sizes + every tamper case (body, root, path hash, SET signature, pubkey substitution, logIndex mutation, missing inclusionProof, pubkey-fetch failure).

After 10.3 + 10.3b: the attacker chain to silently rewrite history is now Haldir's DB + every mirror backend + Rekor's own signing key + every auditor's pinned receipt. Same resistance threshold CT achieves for the WebPKI.

### 10.4 Per-tenant Ed25519 BYOK signing keys
Today, all tenants on a Haldir deployment share one Ed25519 STH-signing key. Future: per-tenant keys, with the public key pinned by the tenant out-of-band. Even Haldir-the-server cannot forge STHs for that tenant once the key is pinned.

### 10.5 Hardware-backed key storage (KMS / HSM)
Today, `HALDIR_TREE_SIGNING_KEY_ED25519` lives in env. Future: AWS KMS / GCP KMS / hardware HSM integration so the private key material never sees process memory.

### 10.6 SOC2 Type II attestation
Today, Haldir produces audit-prep evidence packs RELEVANT to SOC2 — not an attestation. Future: complete a Type II audit cycle with a real CPA firm. Track SOC2 Trust Services Criteria coverage in the readiness score; aim for `pass` on 6/6 criteria before scheduling the audit.

### 10.7 Formal verification of the Merkle verifier
The current verifier is property-tested (10 Hypothesis properties + differential against a naive RFC 6962 reference). A future pass uses Cryptol or F* to give a machine-checked proof of correctness on the verify path. Would be the first AI-agent-governance product to ship a formally-verified crypto core.

---

## 11. Versioning + amendments

This document is versioned at the top. Material changes:

- Threat additions or scope changes bump the major version.
- New mitigations within an existing threat bump minor.
- Typo / clarity fixes are silent.

Each version is committed to git; the diff IS the changelog.

---

*Last review: 2026-04-20. Next scheduled review: 2026-07-20.*
