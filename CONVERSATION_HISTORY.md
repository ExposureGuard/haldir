# Haldir — Conversation History & Decisions Log

This documents the key decisions, insights, and evolution of Haldir from initial idea to platform.

---

## Origin (2026-04-01)

**The spark:** Sterling asked "what if I built a tool/company with a Lord of the Rings name like Haldir and focused exclusively on MCP servers for things that agents need?"

**Initial thesis:** AI agents are about to interact with the entire internet autonomously — browsing, buying, signing up, sending emails, calling APIs, transferring money. There's zero infrastructure layer between the agent and the world. No guardrails, no identity, no trust verification, no audit trail.

**Name meaning:** Haldir was the watchman of Lothlórien — the sentinel who decided who could pass. Perfect for agent security/governance.

---

## Architecture Decisions

### Three Products, One Platform
- **Gate** — Agent identity, scoped sessions, permissions, spend limits
- **Vault** — AES-encrypted secrets, payment authorization, budget enforcement
- **Watch** — Immutable audit log, anomaly detection, cost tracking, compliance

### Proxy Mode (the differentiator)
Added after realizing opt-in governance isn't enough. The proxy sits between agents and all MCP servers, intercepting every tool call. Enforces policies: allow/deny lists, spend limits, rate limits, time windows. This silences the "agents can just bypass it" skeptic.

### Human-in-the-Loop Approvals
When an agent attempts a sensitive action, Haldir pauses execution and waits for human approval. Webhook notifications to Slack/Discord. This is the enterprise killer feature.

---

## Technical Milestones

### Day 1 (2026-04-01)
- Designed Gate, Vault, Watch architecture
- Built core modules with in-memory storage
- Created MCP server with 9 tools (later 10)
- All tests passing
- Bought haldir.xyz domain

### Day 2 (2026-04-02)
- Added SQLite persistent storage
- Built REST API (28+ endpoints)
- Built API key auth system
- Deployed to Railway
- Landing page live at haldir.xyz (SpaceX-inspired, terminal animation)
- Published to Smithery (98/100 score)
- Published to modelcontextprotocol.io
- Submitted to mcp.so, mcpservers.org
- Published to PyPI (`pip install haldir`)
- Created GitHub repo with 19 topics

### Day 3 (2026-04-03)
- Added multi-tenant isolation (tenant_id on every table)
- Added Postgres support (DATABASE_URL env var)
- Added usage tracking for billing
- Built human-in-the-loop approval system
- Built webhook alerting system
- Added rate limiting per tier
- Built API docs page at /docs
- Built MCP JSON-RPC endpoint with 10 tools, 2 prompts, annotations
- Built Python SDK (sync + async clients)
- Added proxy mode — intercepts every MCP tool call
- Added proxy policies: block_tool, allow_list, deny_list, spend_limit, rate_limit, time_window
- Tested proxy with ExposureGuard as upstream — working end-to-end

### Day 4 (2026-04-04)
- Added agent discovery: openapi.json, llms.txt, ai-plugin.json, robots.txt, server-card.json, icon.svg
- Optimized GitHub README with badges, architecture diagram, full endpoint table
- Submitted 8 PRs to awesome lists (87K+ combined stars)
- Created 3 GitHub issues for SEO
- Published GitHub release v0.1.0
- Added Stripe billing integration (pricing page, checkout, webhooks, tier enforcement)
- Built CLI tool (856 lines) — `haldir session create`, etc.
- Built GitHub Action for CI/CD integration
- Built quickstart tutorial page
- Migrated to Postgres (persistent data across deploys)
- Fixed SQLite lock issues, encryption key persistence
- Set HALDIR_ENCRYPTION_KEY and HALDIR_BOOTSTRAP_TOKEN on Railway

### Day 5 (2026-04-05)
- Built JavaScript SDK (zero deps, native fetch)
- Wrote 4 integration guides (LangChain, CrewAI, AutoGen, MCP proxy)
- Wrote 3 SEO blog posts
- Built blog engine with markdown rendering
- Created 4 runnable example scripts
- Created X content calendar (2 weeks pre-written)
- Created 3 ready-to-post X threads
- Submitted to additional directories (PulseMCP auto-indexes from registry)

---

## Business Model

| Tier | Price | Agents | Actions/mo |
|---|---|---|---|
| Free | $0 | 1 | 1,000 |
| Pro | $49/mo | 10 | 50,000 |
| Enterprise | $499/mo | Unlimited | Unlimited |
| Usage overage | $0.001/action | — | After limit |

---

## Distribution Strategy

### Registries (all live)
- Smithery (98/100)
- modelcontextprotocol.io (official Anthropic registry)
- PyPI (`pip install haldir`)
- mcp.so
- mcpservers.org
- GitHub (19 topics, optimized README)

### Awesome List PRs (8 submitted)
1. punkpeye/awesome-mcp-servers (84K stars) — PR #4251
2. rohitg00/awesome-devops-mcp-servers (970 stars) — PR #150
3. Puliczek/awesome-mcp-security (674 stars) — PR #119
4. korchasa/awesome-mcp (~500 stars) — PR #3
5. raphabot/awesome-cybersecurity-agentic-ai (391 stars) — PR #21
6. e2b-dev/awesome-mcp-gateways (112 stars) — PR #44
7. bh-rat/awesome-mcp-enterprise (105 stars) — PR #55
8. ProjectRecon/awesome-ai-agents-security (16 stars) — PR #15

### Agent Discovery Protocols (7)
- /openapi.json — OpenAPI 3.1
- /llms.txt — LLM-readable docs
- /.well-known/ai-plugin.json — ChatGPT plugins
- /.well-known/mcp/server-card.json — MCP discovery
- /mcp — MCP JSON-RPC endpoint
- /robots.txt — crawler-friendly
- /icon.svg — brand icon

### Content
- 7 blog posts (3 general + 4 integration guides)
- 3 X threads pre-written
- 2-week content calendar
- 4 example scripts on GitHub

### X Strategy
- 100 replies/day targeting MCP and AI agent conversations
- 4 posts/day rotating angles (security, technical, vision, social proof)
- 70/30 rule: 70% helpful replies, 30% with natural Haldir mention

---

## Funding Path

### Phase 0: Now → Month 3
- 100 replies/day on X
- Target: 50 users, $2-5K MRR

### Phase 1: Month 3-4
- Apply SC Launch ($50-200K, 50-60% odds with traction)
- Apply YC (S27 batch)
- Apply Techstars, Pioneer, Neo

### Phase 2: Month 4-8
- Get funded or self-fund from revenue
- Quit day job at $5K MRR or when funded
- Hire first 2-3 people (remote)

### Phase 3: Month 8-18
- Scale to $1M ARR
- Series A at $100-150M valuation

### Phase 4: Year 3-5
- $5-40M ARR
- Series B at $800M valuation
- Take $5-10M secondary

### Phase 5: Year 5-8
- $40-120M ARR
- IPO as HLDR on NASDAQ

---

## YC Idea Quality Score (assessed 2026-04-03)

- How big of an idea: **9/10**
- Founder/market fit: **6/10**
- How easy to get started: **10/10**
- Early market feedback: **3/10** ← THE GAP
- **Overall: 7/10**

Action: Every decision prioritizes moving market feedback from 3 to 7+.

---

## The 10% Outcome (North Star)

Year 1: 500 users, 30 paying, $60K ARR, Anthropic partner program
Year 2: Seed raise $5M at $40M. Team of 12.
Year 3: Series A. $15M ARR. $150M valuation. Sterling owns 55%.
Year 4: $40M ARR. AWS/Google launch competitors 18 months behind.
Year 5: Microsoft offers $500M. Say no. Series B at $800M.
Year 7: $200M ARR. Agent-to-agent commerce. Visa network for AI.
Year 8: IPO at $3-5B.
Year 10: $10B+ market cap. Sterling owns 25-30%. $2.5B+ stake.

---

## Key Insights & Principles

1. **"The product is built. The only thing left is distribution."** — Repeated throughout. Haldir has more features than needed for 0 users.

2. **ExposureGuard is the trojan horse.** First tool in the Haldir ecosystem, not a separate product. Revenue from EG funds Haldir development.

3. **The proxy mode is the moat.** Opt-in governance can be bypassed. Proxy mode is enforcement. This is what enterprises need.

4. **Take secondaries, then run it to the moon.** $2-3M at Series A removes desperation. Lets you say no to low acquisition offers.

5. **The 10% outcome diverges from 70% at distribution.** Same product, same market. The difference is 50 cold emails in week 2.

6. **SC Launch is the easiest first funding.** 50-60% odds with $2K MRR. SC angel tax credit (35%) makes local angels easy.

7. **Don't find a cofounder until $5K MRR.** Need a seller, not another builder. 15-20% equity with 4-year vesting.

8. **Stay in Greenville.** Low cost = longer runway. Customers don't care where you live. Hire remote.

9. **100 replies/day.** The distribution grind. Day 1 energy is easy. Day 30 energy builds companies.

10. **"What would the Year 5 version of Sterling do?"** The decision framework question that matters most.

---

## Metrics Tracking

### SC Launch Scoreboard
```
                    Now (Day 5)    Target (Month 3)
API keys:           4              50+
Paying customers:   0              5+
MRR:                $0             $2,000+
X followers:        TBD            500+
Monthly growth:     n/a            30%+
```

### Daily Check
```bash
curl -s https://haldir.xyz/v1/metrics -H "Authorization: Bearer KEY" | python3 -m json.tool
```

---

## Platform Inventory (as of 2026-04-06)

| Component | Status |
|---|---|
| REST API | 30+ endpoints, Postgres |
| MCP Server | 10 tools, 98/100 Smithery |
| Proxy Mode | Policy enforcement, upstream forwarding |
| CLI Tool | Full terminal interface, 856 lines |
| Python SDK | Sync + async, PyPI published |
| JavaScript SDK | Zero deps, ready for npm |
| Dashboard | Sessions, audit, spend, approvals, webhooks |
| Billing | Stripe integration, 3 tiers |
| Blog | 7 articles, markdown engine |
| Docs | API ref, OpenAPI, quickstart, llms.txt |
| Examples | 4 runnable scripts |
| GitHub Action | CI/CD governed sessions |
| Discovery | 7 protocols, 8 awesome-list PRs |
| Database | Postgres (persistent) |
| Landing Page | Live demo, terminal animation |
| Content | 2-week calendar, 3 threads pre-written |

---

*"The watchman of Lothlórien. Nothing passes without his knowledge."*
