# Haldir — Daily Playbook

**Rule:** Do these every single day. No exceptions. The compound effect of daily distribution is the only thing that turns a product into a company.

---

## Morning (30 min)

1. **Check metrics**
```bash
curl -s https://haldir.xyz/v1/metrics -H "Authorization: Bearer YOUR_KEY" | python3 -m json.tool
```
Write down: API keys, actions today, unique agents. Track the trend.

2. **Post on X** — one original post. Rotate these angles:
   - Monday: Security angle ("Your agent has access to your Stripe key...")
   - Tuesday: Technical angle (show code, proxy mode, MCP tools)
   - Wednesday: Vision angle ("Nobody's asking who controls AI agents")
   - Thursday: Social proof (metrics, Smithery score, new users)
   - Friday: Hot take ("AI agents without governance is like servers without auth in 2005")
   - Saturday: Builder story (what you shipped this week)
   - Sunday: Thread (deep dive on one Haldir feature)

---

## Midday (30 min)

3. **Reply to 10 AI/agent tweets** — search "MCP server", "AI agent", "Claude tools", "agent security". Add value first, mention Haldir naturally. Not "check out my product" — give insight, then link.

4. **Send 3 cold DMs or emails** — target:
   - AI agent startup founders (search YC, ProductHunt)
   - DevRel people at Anthropic, OpenAI, Vercel, LangChain
   - CTOs posting about deploying agents
   - Security engineers at companies using AI

---

## Evening (30 min)

5. **Build one thing** — not a new feature. A distribution asset:
   - Monday: Write a short blog post or tutorial
   - Tuesday: Record a 30-sec demo clip
   - Wednesday: Comment on 3 relevant GitHub repos or discussions
   - Thursday: Post in a new community you haven't tried
   - Friday: Email 5 people who signed up but haven't used the API
   - Saturday: Improve the landing page or docs based on feedback
   - Sunday: Plan next week's posts

6. **Check metrics again** — compare to morning. Any new keys? Any new agents?

---

## Weekly (Sunday night, 1 hour)

- Review the week: new API keys, new agents, total actions, any paying users
- Write down what worked and what didn't
- Plan next week's X posts (write drafts)
- Update SOUL.md milestones if anything was achieved
- Ask: "What would the Year 5 version of me do differently?"

---

## Monthly

- Review MRR (ExposureGuard + Haldir)
- Review total users and growth rate
- Decide: do I need to build something, or do I need to sell harder?
- Apply to one accelerator, grant, or program
- Publish a "monthly update" post on X (transparency builds trust)

---

## The Numbers That Matter

| Metric | Week 1 target | Month 1 | Month 3 | Month 6 |
|---|---|---|---|---|
| API keys (users) | 5 | 50 | 200 | 1,000 |
| Daily actions | 10 | 100 | 1,000 | 10,000 |
| Unique agents | 1 | 10 | 50 | 200 |
| Paying customers | 0 | 1 | 5 | 20 |
| MRR | $0 | $49 | $500 | $5,000 |
| X followers | +50 | +200 | +1,000 | +5,000 |

---

## Content Templates (copy and customize)

### Security angle
```
Your AI agent has unrestricted access to:
- Your database credentials
- Your payment API keys  
- Your customer data

No session. No budget limit. No audit trail.

That's not automation. That's a breach waiting to happen.

haldir.xyz
```

### Technical angle
```
10 lines of Python to govern your AI agent:

from haldir import HaldirClient
h = HaldirClient(api_key="hld_xxx")
session = h.create_session("my-agent", scopes=["read", "spend:50"])
h.store_secret("api_key", "sk_xxx")
h.authorize_payment(session["session_id"], 29.99)
h.log_action(session["session_id"], tool="stripe", action="charge")

Identity. Secrets. Audit. One API.

pip install haldir
```

### Vision angle
```
In 2005, servers ran as root with no access controls.
In 2015, APIs shipped without auth tokens.
In 2025, AI agents have unlimited access to everything.

History repeats. The fix is always the same: identity, permissions, audit.

Haldir is that fix for AI agents.

haldir.xyz
```

### Hot take
```
Hot take: 90% of AI agent startups will have a security incident in the next 18 months.

Not because agents are dangerous.
Because nobody built the governance layer.

No session scoping. No spend limits. No audit trail.

We did. haldir.xyz
```

### Social proof
```
Haldir this week:
- X API keys created
- X agent actions proxied
- X secrets stored
- 98/100 on Smithery
- 0 security incidents

The governance layer for AI agents is live.
haldir.xyz
```

---

## The One Rule

**Never go to bed without having posted at least once and replied to at least 5 people.** The algorithm rewards consistency. Your future users are scrolling right now. Be there when they look.

---

*Reference SOUL.md for the north star. This playbook is how you get there daily.*
