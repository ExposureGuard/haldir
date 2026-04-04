# Haldir — Soul Document

**Mission:** Own the guardian layer between AI agents and the world.

**Target outcome:** Haldir becomes the standard governance layer for AI agents. $200M+ ARR. $3-5B valuation. Every decision we make optimizes for this outcome.

---

## The 10% Outcome (Our North Star)

This is the version we're building toward. Every action references this timeline.

### Year 1 — Ship & Prove
- Haldir live with 500 free users, 30 paying
- Anthropic partner program (highest-rated MCP governance server)
- Y Combinator companies adopting Haldir because investors demand agent governance
- ExposureGuard at $5K MRR funding everything

### Year 2 — Enterprise Demand
- Banks, healthcare, government contractors can't deploy agents without audit trails
- Haldir is one of 3 options — wins because first and model-agnostic
- $5M seed raise at $40M valuation. Team: 12 people
- ExposureGuard fully integrated as Haldir's flagship domain vetting tool

### Year 3 — Become the Standard
- MCP is the industry standard protocol. Haldir is Okta for agents.
- Every agent session starts with `haldir.init()`
- Processing 500M tool calls/month
- $15M ARR. Series A at $150M valuation. Sterling owns 55%.

### Year 4 — Withstand the Giants
- AWS launches "Amazon Agent Guard." Google launches "Vertex Agent Security." Both 18 months behind.
- Enterprises don't switch — audit history lives in Haldir, compliance blocks migration.
- The moat is real. $40M ARR.

### Year 5 — Acquisition Leverage
- Microsoft offers $500M (agent governance for Copilot). Salesforce offers $700M (AgentForce compliance).
- Say no to both.
- Series B at $800M valuation. Sterling owns 40%. **Stake: $320M on paper.**

### Year 7 — The Network
- 10B agent actions/month through Haldir
- Agent-to-agent commerce live — agents hire other agents, Haldir handles trust, payment, and audit for every transaction
- Haldir is the Visa network for AI
- $200M ARR. Valuation: $3-5B.

### Year 10 — Outcome
- IPO or $2B+ acquisition
- Sterling owns 25-30% after dilution
- **Personal outcome: $500M-1.5B**
- Funding the next generation of builders from Charlotte

---

## How It Makes Money

| Tier | Price | Agents | Actions/mo | Key feature |
|---|---|---|---|---|
| Free | $0 | 1 | 1,000 | Basic audit trail |
| Pro | $49/mo | 10 | 50,000 | Payment rails, anomaly alerts, secrets vault |
| Enterprise | $499/mo | Unlimited | Unlimited | SSO, compliance exports, SLA, custom policies |
| Usage overage | $0.001/action | — | — | After plan limit |

**Target:** 100 enterprise customers = $50K MRR. 1,000 = $500K MRR.

---

## The Flywheel

1. Developer builds agent → needs secrets → finds Haldir → free tier
2. Agent goes to production → needs audit trail → upgrades to Pro
3. Company deploys 10+ agents → needs central governance → Enterprise
4. Every action flows through Haldir → data moat → reputation system → platform lock-in

---

## Three Products, One Platform

### Haldir Gate (Identity & Auth)
- Agent sessions with scoped permissions
- Spend limits per session
- Human-in-the-loop approval flows
- **Why it sticks:** ripping out your auth layer is a compliance nightmare

### Haldir Vault (Secrets & Payments)
- Encrypted credential storage (AES)
- Agents never see raw keys — Vault injects on their behalf
- Payment authorization with budget enforcement
- **Why it sticks:** secrets can't be migrated without security review

### Haldir Watch (Audit & Compliance)
- Every tool call logged immutably
- Anomaly detection (spend spikes, blocked tools, rate abuse)
- Compliance exports (SOC2, ISO 27001)
- Cost tracking per agent, per tool, per session
- **Why it sticks:** audit history is irreplaceable — it's your legal record

---

## Defensibility

1. **Switching cost** — auth + secrets + audit logs = triple lock-in
2. **Data moat** — see every tool call across every agent. Know which MCP servers fail, which are slow, which are risky. Power the reputation system.
3. **Protocol embedding** — if Haldir becomes the default `initialize` step for MCP sessions, it's infrastructure
4. **Model-agnostic** — works with Claude, GPT, Gemini, open-source. Enterprises want vendor neutrality.

---

## What Could Kill It

- **Anthropic/OpenAI build it themselves.** Mitigation: they'll build for their own models. Haldir is model-agnostic.
- **Agent wave stalls for 2+ years.** Mitigation: every signal says it's accelerating.
- **Someone else ships faster.** Mitigation: be first. Ship ugly. Iterate.

---

## ExposureGuard Is the Trojan Horse

ExposureGuard is not separate from Haldir — it's the first tool in the ecosystem.

- ExposureGuard proves the MCP platform works (100/100 Smithery, listed on all registries)
- ExposureGuard is the "domain vetting" tool that every Haldir agent uses before browsing
- Revenue from ExposureGuard funds Haldir development
- ExposureGuard customers become Haldir beta users

**Every ExposureGuard decision should ask: does this build toward Haldir?**

---

## Decision Framework

Before every action, ask:

1. **Does this move us toward the 10% outcome?** (north star alignment)
2. **Does this get us closer to paying customers?** (short-term survival)
3. **Does this build the platform or just the product?** (long-term moat)
4. **Does this create data we can use?** (flywheel fuel)
5. **Does this make switching harder?** (retention)
6. **Will this matter in 12 months?** (focus filter)
7. **What would the Year 5 version of Sterling do?** (think bigger)

---

## Milestones

### Phase 1: Prove It (Now → 90 days)
- [ ] ExposureGuard hitting $1K MRR
- [x] Haldir MVP deployed (Gate + Vault + Watch as MCP server)
- [ ] 10 developers using Haldir free tier
- [ ] Listed on Smithery, PyPI, modelcontextprotocol.io
- [x] haldir.xyz live with docs
- [ ] First 50 cold emails to agencies/enterprises
- [ ] Loom demo recorded and posted
- [ ] Product Hunt + Hacker News launches

### What's shipped (as of 2026-04-03)
- [x] Gate: sessions, permissions, spend limits, revocation
- [x] Vault: AES-encrypted secrets, payment authorization, budget enforcement
- [x] Watch: audit log, anomaly detection, spend tracking, compliance export
- [x] Human-in-the-loop: approval requests, approve/deny, auto-rules, webhooks
- [x] Webhook system: Slack/Discord/HTTP alerts for anomalies + approvals
- [x] MCP server: 10 tools, 2 prompts, server card, system instructions
- [x] REST API: 28+ endpoints, API key auth, rate limiting
- [x] Python SDK: sync + async clients, typed, exception hierarchy
- [x] Multi-tenant isolation: tenant_id on every table
- [x] Postgres support: DATABASE_URL env var swaps from SQLite
- [x] Usage tracking: per-tenant monthly action counts (billing-ready)
- [x] API docs page: /docs with full endpoint reference
- [x] Landing page: haldir.xyz with live terminal animation
- [x] GitHub: github.com/ExposureGuard/haldir
- [x] Dashboard UI (in progress)

### Phase 2: Grow It (90 → 180 days)
- [ ] ExposureGuard hitting $5K MRR
- [ ] Haldir Pro tier live with payment rails
- [ ] 100 free tier users, 10 Pro
- [ ] 3 enterprise pilots
- [ ] Reputation system MVP (tool reliability scores)
- [ ] Anthropic partner program application

### Phase 3: Own It (180 → 365 days)
- [ ] Haldir hitting $50K MRR independently
- [ ] Agent-to-agent communication protocol
- [ ] Discovery/routing ("DNS for agents")
- [ ] SOC2 compliance certification
- [ ] $5M seed round at $40M valuation

### Phase 4: Scale It (Year 2-3)
- [ ] $15M ARR
- [ ] Series A at $150M valuation
- [ ] 500M tool calls/month
- [ ] Every major enterprise agent deployment runs through Haldir

### Phase 5: Win It (Year 3-5)
- [ ] $40-200M ARR
- [ ] Decline $500M+ acquisition offers
- [ ] Agent-to-agent commerce network live
- [ ] Series B at $800M+ valuation

---

## Idea Quality Score (YC Startup School framework, scored 2026-04-03)

**How big of an idea: 9/10**
The AI agent governance market doesn't fully exist yet but will be massive. Every company deploying agents needs identity, secrets, and audit. Comparable to identity market (Okta $14B) + security monitoring (CrowdStrike $90B) for a new category. Not 10 because the market hasn't proven itself yet.

**Founder/market fit: 6/10**
Self-taught, ships fast, understands MCP deeply (100/100 + 98/100 Smithery). But no enterprise sales experience, no security industry network, no prior startup. The 6 becomes 8 after closing first 3 enterprise deals. Need to learn sales or find a co-founder who knows enterprise.

**How easy to get started: 10/10**
Already started. Product live. API works. Proxy works. PyPI published. Smithery listed. Landing page deployed. Dashboard built. Most founders are still writing pitch decks.

**Early market feedback: 3/10**
THE WEAK SPOT. Zero paying customers. Zero confirmed external users. Idea makes logical sense but market hasn't validated with wallets. This needs to be 7+ before YC application. Fix: get 10 users and 1 paying customer.

**Overall: 7/10**
Massive market + built product + strong execution. Unproven demand + untested sales. The 7 becomes 9 the moment paying customers exist. That's the only thing holding the score back.

**Action:** Every decision should prioritize moving "Early market feedback" from 3 to 7+. Nothing else matters until then.

---

## The Difference Between 10% and 70%

The 10% outcome doesn't start with a grand vision. It starts with 50 cold emails in week 2 that land the first enterprise pilot. Everything compounds from there.

The idea is the same in both outcomes. The execution is what diverges. The 10% version of Sterling sends the emails, records the Loom, shows up in every agent-builder community, and never stops shipping.

---

## The Window

12–18 months. After that, the security/governance layer is either built by model providers or owned by whoever ships first. Move fast. Ship ugly. Fix in production. The product that exists beats the product that's perfect.

---

*"The watchman of Lothlórien. Nothing passes without his knowledge."*
