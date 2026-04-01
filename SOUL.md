# Haldir — Soul Document

**Mission:** Own the guardian layer between AI agents and the world.

---

## The Thesis

Every AI agent needs identity, secrets, and accountability before it can act in the real world. Nobody owns this layer. MCP is the protocol. Haldir is the security/governance middleware. First to ship wins.

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

1. **Does this get us closer to 3 paying customers?** (short-term survival)
2. **Does this build the platform or just the product?** (long-term moat)
3. **Does this create data we can use?** (flywheel fuel)
4. **Does this make switching harder?** (retention)
5. **Will this matter in 12 months?** (focus filter)

---

## Milestones

### Phase 1: Prove It (Now → 90 days)
- [ ] ExposureGuard hitting $1K MRR
- [ ] Haldir MVP deployed (Gate + Vault + Watch as MCP server)
- [ ] 10 developers using Haldir free tier
- [ ] Listed on Smithery, PyPI, modelcontextprotocol.io
- [ ] haldir.xyz live with docs

### Phase 2: Grow It (90 → 180 days)
- [ ] ExposureGuard hitting $5K MRR
- [ ] Haldir Pro tier live with payment rails
- [ ] 100 free tier users, 10 Pro
- [ ] 3 enterprise pilots
- [ ] Reputation system MVP (tool reliability scores)

### Phase 3: Own It (180 → 365 days)
- [ ] Haldir hitting $50K MRR independently
- [ ] Agent-to-agent communication protocol
- [ ] Discovery/routing ("DNS for agents")
- [ ] SOC2 compliance certification
- [ ] Seed round or profitable — founder's choice

---

## The Window

12–18 months. After that, the security/governance layer is either built by model providers or owned by whoever ships first. Move fast. Ship ugly. Fix in production. The product that exists beats the product that's perfect.

---

*"The watchman of Lothlórien. Nothing passes without his knowledge."*
