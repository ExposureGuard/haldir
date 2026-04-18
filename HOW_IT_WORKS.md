# How Haldir Works

The guardian layer for AI agents — in plain English.

---

## The Problem

A developer is building an AI agent. The agent needs to call APIs — Stripe, GitHub, internal systems. Without Haldir, the agent has direct access to everything:

- Full API keys in plaintext
- No spend limits
- No permission scopes
- No audit trail
- No way to stop a misbehaving agent

When the CISO asks "what did the agent do last week?" the answer is "we don't know."

---

## The Flow

1. **Developer creates an API key** at haldir.xyz. Gets `hld_xxx`.

2. **Developer creates a session for their agent:**
   ```python
   create_session("my-agent", scopes=["read", "spend:50"])
   ```
   Returns `ses_xxx`. The agent now has an identity, a permission list, and a $50 budget.

3. **Developer stores secrets in Haldir's vault:**
   ```python
   store_secret("stripe_key", "sk_live_xxx")
   ```
   The raw key never touches the agent — it's encrypted with AES-128 at rest.

4. **The agent calls tools through Haldir's proxy.** Instead of the agent calling Stripe directly, it calls `haldir.xyz/v1/proxy/call` with the tool name and arguments. Haldir:
   - Checks the session is valid
   - Checks the scope matches the action
   - Checks the agent's budget against the spend
   - Checks policy rules (allow/deny lists, rate limits, time windows)
   - Forwards the call to the real tool (Stripe)
   - Logs the entire action to the hash-chained audit trail
   - Returns the result to the agent

5. **If the action needs human approval** (e.g. spend > $100), Haldir pauses the agent, fires a webhook to Slack, and waits for the human to approve or deny.

6. **The agent can't bypass Haldir** because it never has the raw Stripe key — it only knows how to call Haldir's proxy.

7. **When the agent is done,** the developer revokes the session. All access is cut instantly.

---

## The Three Components

### Gate — Identity & Permissions
- Scoped sessions with TTL
- Per-session spend limits
- Permission checks before every action
- Instant revocation (kill switch)

### Vault — Encrypted Secrets & Payments
- AES-128 encrypted secret storage
- Agents never see raw credentials
- Payment authorization against session budget
- Scope-checked access control

### Watch — Immutable Audit Trail
- Every action logged with agent ID, session ID, tool, cost, timestamp
- Hash-chained for tamper evidence
- Anomaly flagging rules
- Compliance-ready exports

### Proxy — The Enforcement Layer
- Sits between agent and tools
- Every tool call intercepted and authorized
- Policy enforcement (allow/deny, rate limits, time windows)
- Human-in-the-loop approval hooks

---

## Why It Sticks

Once a customer's audit logs live in Haldir, they can't leave without losing their compliance record. Once their secrets are in the vault, they can't migrate without a security review. Once every agent is wired through the proxy, switching means rewiring every agent.

The longer they use it, the harder it is to leave.

---

## Try It

```bash
curl -X POST https://haldir.xyz/v1/demo/key \
  -H "Content-Type: application/json"
```

Gets you a free API key instantly. Or visit [haldir.xyz/quickstart](https://haldir.xyz/quickstart) for the interactive walkthrough.
