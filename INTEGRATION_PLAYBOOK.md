# Integration Partnership Playbook

The real playbook: you don't "land" an integration partnership — you **build it first, prove it works publicly, then get it blessed**. Cold pitching from a solo founder with 2 GitHub stars goes nowhere.

## The 4-step pattern that actually works

1. Build the integration yourself (no permission needed)
2. Ship a killer demo/tutorial that uses it
3. Get real users to adopt it and post about it
4. Then DM the target company's DevRel with proof ("here's the integration, here's 500 users, can you feature it?")

---

## Pick ONE target this week

### Tier A — highest leverage, most accessible

1. **LangChain** — they publish third-party integrations freely. Ship `langchain-haldir` as a PyPI package, PR docs to their integrations page, write a tutorial. Harrison Chase (@hwchase17) retweets good community work.
2. **CrewAI** — smaller ecosystem, more accessible founder (João Moura), and agent-focused so Haldir's pitch is native. Easier win.
3. **Continue.dev** — open-source, small team, very welcoming to contributors. Their Discord is active.

### Tier B — harder but bigger payoff

4. **Cursor** — MCP native, huge user base. Contact: engage in their Discord with quality answers for 2 weeks before DMing anyone. Cold DMs fail.
5. **Windsurf (Codeium)** — MCP-native IDE, Varun is on X.
6. **Anthropic (Claude Desktop)** — hardest. Need proven usage first. Alex Albert / Logan Kilpatrick-level DevRel.

---

## The tactical sequence (3 weeks)

### Week 1 — Build the integration

Pick LangChain. Ship:

- `pip install langchain-haldir` — drop-in governance wrapper for any LangChain agent
- 30-line example: "wrap any LangChain agent in Haldir in 30 seconds"
- README with before/after screenshots (audit trail, spend cap, revocation)

### Week 2 — Demo and distribute

- Record a 2-min Loom: "I gave my LangChain agent $10K and it couldn't spend more than $50"
- Post to: Hacker News (Show HN), r/LocalLLaMA, LangChain's Discord, Haldir's audience
- Write a LangChain blog-style tutorial on dev.to and your own blog

### Week 3 — Ask for the blessing

Once 50-100 people have installed it:

- PR to LangChain's `docs/docs/integrations/providers/haldir.ipynb`
- DM Harrison Chase with the tweet about your integration that has 20+ likes
- Email partnerships@langchain.com with usage numbers
- Tag them in every post

---

## What NOT to do

- Cold email "Hi, I'd love to partner." Zero response rate.
- Pitch Anthropic first — too high. Prove yourself in tier A first.
- Build 5 integrations shallowly. Build ONE deeply.
- Wait for permission before shipping the code.

---

## Template DM for after you have traction

> Hi [Name] — I built a governance layer for LangChain agents (audit trails, spend caps, secrets vault). Shipped it 2 weeks ago, 120 installs so far, [user X] posted about it [link]. Happy to PR it to your integrations docs. Would love your feedback on the approach. haldir.xyz

Ship first, ask second.
