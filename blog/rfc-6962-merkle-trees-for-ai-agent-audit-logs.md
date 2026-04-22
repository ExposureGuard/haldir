# RFC 6962 Merkle Trees for AI-Agent Audit Logs

*Published: April 2026 | Tags: AI agent security, cryptographic audit, RFC 6962, Certificate Transparency, tamper evidence, Ed25519, Sigstore Rekor, MCP*

> *"Your AI agent just refunded $12,000 to the wrong customer. Your auditor wants cryptographic proof of what happened. Your log? A text file your own DBA can rewrite."*

That line sits on Haldir's landing page. It lands because it is the actual failure mode — not a thought experiment. AI agents are shipping to production with real tool-calling authority: Stripe refunds, database writes, code pushes, outbound email. When one misbehaves, the thing that protects the company is the audit trail. For most teams, that audit trail is a Postgres table or a CloudWatch stream — append-only, which means an agent can't rewrite it, but the operator can. When an auditor, a regulator, or a board member asks *"prove this log is exactly what your agent actually did"*, the honest answer today is *"trust me."*

The security industry solved this problem for TLS certificates twelve years ago. The solution is **RFC 6962**, and the primitive it defines — a cryptographically verifiable Merkle-tree log with signed tree heads — keeps seven billion active TLS certificates honest via [Certificate Transparency](https://certificate.transparency.dev/). This post is about applying the exact same primitive to AI-agent audit logs, which is the job [Haldir](https://haldir.xyz) does.

You can click the primitive live at [haldir.xyz/demo/tamper](https://haldir.xyz/demo/tamper) — mutate a database row and watch the crypto reject it in real time. If you learn better by reading, keep going.

---

## What "tamper evidence" actually means

There are two properties worth distinguishing.

**Tamper resistance** is what a ledger, an object-lock S3 bucket, or a WORM database gives you: the system refuses to accept changes to history. This is useful, but it lives inside one trust boundary. The operator of the ledger holds the keys. If the ledger itself is compromised or subpoenaed, the resistance evaporates.

**Tamper evidence** is the cryptographic property that says: *if history was changed, anyone holding a prior commitment can detect it.* The system can't stop a rewrite, but the rewrite can't hide. This is the property Certificate Transparency provides for the WebPKI. A malicious CA can in theory issue a rogue certificate, but once any monitor sees the log's Signed Tree Head and records it, the CA can't quietly un-issue that certificate or swap it for a different one without breaking the commitment every monitor holds.

For AI-agent audit logs, tamper evidence is the property you want. You're not trying to prevent the log from being edited — you're trying to guarantee that if an edit happens, it shows up as a cryptographic failure, not a silent diff. That's the property an auditor, a regulator, and a board actually care about.

---

## The RFC 6962 primitive in three pictures

RFC 6962 defines three artifacts. Each does one job.

**1. The Merkle tree itself.** Every audit entry becomes a leaf in a binary hash tree. Leaves are hashed as `H(0x00 || entry_bytes)`, internal nodes as `H(0x01 || left || right)`. The root of the tree is a 32-byte SHA-256 value that commits to every entry that came before it. Add one entry, the root changes deterministically. Modify a historical entry, the root also changes — but to a value nobody predicted. That's the commitment.

**2. The Signed Tree Head (STH).** The server signs `(tree_size, root_hash, signed_at)` with a private key and publishes the resulting signature. An auditor who holds an old STH — say, from last quarter — can independently check every new STH and detect if the history below them has been rewritten.

**3. Proofs that verify offline.**

- *Inclusion proof:* given an entry and the current STH, a log-sized sibling-hash path lets anyone recompute the root and check that the entry is in the tree at the position the server claimed. This verifies with no server involvement beyond the initial STH fetch.
- *Consistency proof:* given two STHs for the same log at different tree sizes, a path of hashes proves that the larger tree is an append-only extension of the smaller one. Nothing was removed. Nothing was rewritten in the middle.

These three artifacts compose into a system where *nobody has to trust the log operator for history integrity*. They trust the math and their own pinned STH.

---

## Haldir's shape: audit log as a Merkle tree

Every action an agent takes via Haldir writes a row to the `audit_log` table — the standard append-only shape every logging system uses. On top of that, Haldir computes a per-tenant RFC 6962 Merkle tree whose leaves are the canonical byte encoding of each audit entry, ordered by timestamp.

The canonical leaf-bytes encoding looks like this:

```
{entry_id}|{session_id}|{agent_id}|{action}|{tool}|{details}|{cost_usd:.2f}|{ts_int}|{flagged}|{prev_hash}
```

Pipe-delimited, fixed field ordering, 2-decimal cost formatting, integer timestamp. The exact bytes an auditor reconstructs from the public audit-entry fields. If they reconstruct the leaf hash and the server-claimed root differs, the entry has been mutated.

The tree is recomputed on demand — no precomputed internal-node cache. At current scale (tens of thousands of entries per tenant) this takes sub-millisecond per thousand leaves. When we cross the scaling threshold where caching matters, the obvious move is to store precomputed internal-node hashes keyed by `(tenant, tree_size)`. For now, the pure-function shape makes verification trivially easy to reason about.

### Signed Tree Heads: Ed25519, not HMAC

Haldir supports two signature algorithms for STHs:

**HMAC-SHA256** is the default. Fast, zero-dependency (stdlib only), back-compatible with every v0.3.0 client. The downside: anyone with enough key material to verify has enough to forge. Fine when the auditor trusts the server holding the key.

**Ed25519** is the asymmetric upgrade. Set `HALDIR_TREE_SIGNING_KEY_ED25519_SEED` and every STH is signed with a private key the server holds, while the public key is published at `/.well-known/jwks.json` as an [RFC 7517 JWK](https://datatracker.ietf.org/doc/html/rfc7517). Same shape Okta, Auth0, Supabase, and Sigstore publish their OKP keys. An auditor pins the `kid` at enrollment; they can verify every later STH offline, *and* the verification key can't be used to forge new ones. That's a genuinely different trust story than the HMAC version.

Setting the env variable flips every STH response to Ed25519 — no flag-day migration, no client recompile.

### Verifying offline: what an auditor actually does

The Haldir Python SDK re-exports the verification primitives so the auditor doesn't have to install anything Haldir-specific beyond `pip install haldir`:

```python
from haldir import verify_inclusion_proof, verify_consistency_proof, verify_sth

# An auditor received this receipt from Haldir last quarter.
receipt = {...}  # inclusion proof JSON

# Step 1: is the STH genuinely signed by Haldir's pinned key?
assert verify_sth(receipt["sth"], pinned_public_key_bytes)

# Step 2: is this specific entry in the tree the STH commits to?
assert verify_inclusion_proof(receipt)

# Step 3 (next year): does today's tree extend last quarter's tree?
assert verify_consistency_proof(consistency_receipt)
```

Three calls, zero network hops to Haldir, zero trust in the Haldir server beyond the public key the auditor pinned a year ago.

---

## Anti-equivocation: who watches the watchman?

The Merkle tree and STH together answer the question *"has an individual entry been mutated?"* But they don't answer the harder meta-question: *"has the server ever shown two different STHs to two different auditors at the same tree size?"* A server could sign `tree_size=1000 → root_A` to auditor X and `tree_size=1000 → root_B` to auditor Y, and absent gossip between the auditors, neither would know.

Haldir closes this via a **self-published STH log**. Every STH the server signs is also persisted to a per-tenant append-only table keyed on `(tenant_id, tree_size)`. The primary key enforces idempotency at the schema layer: the first observation of each tree size wins, and any attempt to write a second STH for the same size is a no-op. The log is queryable:

```
GET /v1/audit/sth-log?since=N     # auditor pulls full history
GET /v1/audit/sth-log/verify?pinned_size=N&pinned_root=H
```

The verifier returns one of three outcomes:

- **`match`** — the recorded row at `pinned_size` has `pinned_root`. The auditor's pin is valid; no equivocation.
- **`equivocation`** — the recorded row has a *different* root at that tree_size. This is cryptographic proof of misbehaviour, with both root values in the response for the auditor to disclose.
- **`not_in_log`** — no row at that size. Either the pinned STH predates the log's retention, or it was forged. A helpful `note` disambiguates.

An auditor pins an STH at enrollment and calls `verify` a year later with one GET. If Haldir has ever rewritten history or equivocated, the endpoint says so.

---

## The external mirror: beyond Haldir's trust boundary

The self-published log is strong, but it's defeatable by a single compromised process with write access to both `audit_log` and `sth_log` in the same transaction. The residual named in [Haldir's public threat model](https://haldir.xyz/THREAT_MODEL.md) as §10.3.

The closer: on every signed STH, Haldir additionally publishes the signed bytes to a log that lives *outside* Haldir's trust boundary. Three backends ship today:

- `file:<path>` — append-only JSONL on disk. Good for development plus an on-disk operator log that a separate process archives to a WORM bucket.
- `http://...` — generic POST to any HTTP endpoint that returns an identifier. Bridges to whatever immutable archive a customer already runs.
- `rekor[:url]` — [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) integration. The same transparency log that records cosign signatures for every major open-source artifact — Linux kernel, Kubernetes, npm's Sigstore-signed packages, and growing. Haldir sends a `hashedrekord` entry binding the canonical-STH SHA-256 digest to the Ed25519 public-key PEM + signature. Rekor returns a UUID and log index; Haldir stores them alongside the STH.

A coordinated attacker trying to rewrite Haldir's audit history now has to compromise Haldir's DB + every mirror backend + every auditor's pinned receipt, *simultaneously*, without triggering any external monitor. That's an attack-cost escalation of multiple orders of magnitude — same resistance threshold Certificate Transparency achieves for the WebPKI.

And because the mirror step can be spoofed by a lying facilitator (what if the mirror backend hands back a fabricated UUID?), Haldir ships an independent verifier for Rekor receipts: `haldir.verify_rekor_receipt(receipt)` runs a full RFC 6962 inclusion proof plus ECDSA-P-256 verification against Rekor's own published public key. An auditor can confirm any stored receipt is actually in Rekor's real log, without trusting Haldir.

---

## Two lines of LangChain, end to end

The whole system shows up in agent code as two lines:

```python
from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI
from langchain_haldir import HaldirSession   # line 1

agent = create_react_agent(ChatOpenAI(model="gpt-4o-mini"), tools, prompt)

with HaldirSession.for_agent("refund-bot",   # line 2
                             scopes=["stripe:refund"],
                             spend_limit=50.0) as haldir:
    executor = AgentExecutor(agent=agent, tools=tools,
                             callbacks=[haldir.handler])
    result = executor.invoke({"input": "refund charge ch_abc"})

# result["_haldir_sth"] is the Signed Tree Head that covers every
# tool call and LLM call this agent made. Save it next to the
# run's output; verify offline any time later.
```

Every tool call becomes a leaf in the Merkle tree. Every LLM call is cost-tracked against the session's spend limit. The current STH is stamped onto the run's output so the caller pins it without a separate API call. The session is revoked automatically on scope exit, even on exception.

Same pattern ships for `crewai-haldir` and `llamaindex-haldir` — different framework-specific hooks, identical contract. And for MCP clients (Claude Desktop, Cursor, Windsurf), `haldir mcp serve` exposes all eighteen Haldir tools as an MCP stdio server that installs via one JSON block.

---

## What this is not

Worth naming plainly:

- **This is not a SOC2 attestation.** Haldir generates signed audit-prep evidence packs that map to SOC2 Trust Services Criteria (CC5.2, CC6.1, CC6.7, CC7.2, CC7.3, CC8.1), but an attestation requires a human auditor. What Haldir does is give that auditor something defensible to look at.

- **This does not prevent an agent from doing the wrong thing.** It proves what the agent did, and gates what it's authorized to do. Prompt-injection mitigations, output validation, and tool allow-listing live at different layers.

- **This does not replace your SIEM.** Haldir's audit log is opinionated and narrow — it captures AI-agent actions, not full system-level events. It complements SIEM ingestion rather than replacing it (and exports to CSV or JSONL for that pipeline).

---

## Try it

- **Live adversarial demo** (click *Tamper*, watch the crypto catch it): [haldir.xyz/demo/tamper](https://haldir.xyz/demo/tamper)
- **Full threat model** (STRIDE per component, named adversaries, honest residual-risk declarations): [haldir.xyz/THREAT_MODEL.md](https://haldir.xyz/THREAT_MODEL.md)
- **Install**: `pip install haldir`
- **LangChain**: `pip install langchain-haldir`
- **Source**: [github.com/ExposureGuard/haldir](https://github.com/ExposureGuard/haldir)

The primitive is old. The application is new. Agents need tamper-evident audit logs for the same reason the WebPKI needed them in 2013 — when the stakes are real and the operator can't be unconditionally trusted, the math has to carry the weight.
