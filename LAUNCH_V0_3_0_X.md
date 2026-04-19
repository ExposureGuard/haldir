# Haldir v0.3.0 — X launch kit

Plain text, no emojis, no exclamation marks. Pick ONE of the formats
below as the main post; the rest are variations + reply bait.

Best windows for AI/dev infra on X (ET):
  Tue/Wed/Thu 8:30 am, 12:30 pm, 5:30 pm

Have these tabs open before posting:
  - https://github.com/ExposureGuard/haldir   (so you can pin in replies)
  - https://pypi.org/project/haldir            (verify v0.3.0 is live)
  - https://haldir.xyz/demo                    (the playground)
  - The `haldir overview` screenshot (more on this below)

---

## The screenshot

Run this in a terminal that has good fonts (iTerm2, Alacritty, kitty),
take a screenshot of the output, and use it as the image attachment on
the headline tweet:

    pip install --upgrade haldir
    haldir login
    haldir overview

If you don't want to use a real tenant, ship the README's CLI block as
the image — it's already cleaned up and demo-ready. Open
README.md, find the `haldir overview` block, paste the inside of the
fenced code block into a fresh terminal window, take the screenshot.

The overview output IS the launch — bare ASCII looks more credible than
a marketing graphic.

---

## OPTION A — Single power-tweet (recommended; lowest friction)

> Haldir 0.3.0 is on PyPI.
>
> One install, one command, every governance signal an AI agent stack
> needs in a single dashboard:
>
>     pip install haldir
>     haldir overview
>
> Scoped sessions, encrypted vault, hash-chained audit, signed webhooks,
> and a live status pill — all in 30 lines on your terminal.
>
> github.com/ExposureGuard/haldir

(Attach: `haldir overview` screenshot.)

Why this works: zero ask, one screenshot, one install line, one link.
Reply replies and quote tweets carry the rest.

---

## OPTION B — Thread (use if you want to tell the whole story)

**Tweet 1 (the hook + screenshot)**

> Shipped Haldir 0.3.0 today.
>
> One pip install, one command, every governance signal a serious AI
> agent stack needs in a single dashboard:
>
>     pip install haldir
>     haldir overview
>
> Scoped sessions, encrypted vault, hash-chained audit, signed webhooks,
> and a live status pill in 30 lines on your terminal.

(Attach: screenshot of `haldir overview`.)

**Tweet 2 (the numbers — the credibility build)**

> Real production-grade benchmark, single 12th-gen i3, 4 gunicorn
> workers, full middleware stack on every request (auth, validation,
> idempotency, metrics, structured logging):
>
>   POST /v1/audit       1,247 RPS   p50 25 ms   p99 41 ms
>   POST /v1/sessions    1,266 RPS   p50 25 ms   p99 35 ms
>   GET  /healthz        1,822 RPS
>
> Run it yourself: `python bench/bench_http.py`

**Tweet 3 (the differentiator)**

> Why this exists: every AI agent stack I've watched ships with the same
> three holes.
>
>   1. Agent has unlimited scope. No way to revoke mid-run.
>   2. Secrets live in env vars the LLM can read.
>   3. No cryptographic record of what the agent actually did.
>
> Haldir closes all three at the protocol layer, not the application
> layer. MIT-licensed, self-host or hosted.

**Tweet 4 (the audit angle — for the compliance crowd)**

> The audit trail is hash-chained. Every entry's SHA-256 is computed
> over its contents plus the previous entry's hash. Tamper-evident by
> construction.
>
> 0.3.0 also ships a streaming export endpoint with a signed integrity
> manifest so an auditor can re-verify an archived export offline.
>
> CSV or JSONL, ISO-8601 since/until filters.

**Tweet 5 (the integrations)**

> Native wrappers for the four agent frameworks people actually ship:
>
>   - LangChain      (HaldirCallbackHandler + GovernedTool)
>   - CrewAI         (govern_tool wraps any BaseTool)
>   - AutoGen        (async runtime composition)
>   - Vercel AI SDK  (TypeScript, npm install haldir)
>
> Ten lines to add governance to any existing agent.

**Tweet 6 (the close + ask)**

> Open source from day one, MIT, self-host with `docker compose up` or
> point at the hosted API at haldir.xyz. Same SDKs either way.
>
> Looking for 5 design partners shipping AI agents to prod. 30 days
> free, direct line to me.
>
> Repo: github.com/ExposureGuard/haldir
> Demo: haldir.xyz/demo

---

## OPTION C — Quote-tweet bait (controversial single)

For when you want engagement on a specific angle. Pick ONE.

> Most AI agent "platforms" you can buy today do not have:
>   - per-session spend caps
>   - tamper-evident audit trail
>   - a kill switch you can fire mid-run
>
> Haldir 0.3.0 has all three. MIT-licensed. pip install haldir.
>
> github.com/ExposureGuard/haldir

> Hot take: if your AI agent doesn't have a Stripe-style idempotency
> key on every action, you don't have an agent — you have a footgun.
>
> Haldir 0.3.0 ships idempotency on every mutating POST. With tests.
>
> github.com/ExposureGuard/haldir

> The audit log most "AI observability" tools ship is mutable JSON
> in a Postgres row. The first time a regulator asks for proof of
> integrity you find out.
>
> Haldir's audit chain is SHA-256, hash-of-hash, exportable, signed.
> 0.3.0 just shipped.

---

## OPTION D — Reply-to-self thread starter (if main tweet takes off)

Use these as one-off replies under your own headline tweet to keep the
post alive across the day. Each is self-contained.

> Thing I'm proudest of in 0.3.0: the migration runner.
>
> Forward-only, checksum-verified, dialect-aware (one source serves
> SQLite + Postgres). Catches the silent-edit anti-pattern that wrecks
> production schemas: edit a migration after apply, the next boot logs
> a structured WARNING with both hashes.

> Subtle thing in 0.3.0: every webhook fire gets a UUID event_id, sent
> as X-Haldir-Webhook-Id, retries on 5xx with backoff, and EVERY attempt
> is logged in a queryable deliveries table.
>
> haldir webhooks deliveries --event-id ev_abc...
>
> No more guessing whether the webhook reached the receiver.

> /livez and /readyz are split, like serious K8s deploys want them.
>
> /livez is no-IO, always 200 if the process responds.
> /readyz checks DB reachability + migration consistency + encryption
> key, returns 503 if any check fails.
>
> Most AI infra ships a single /healthz that returns 200 even when
> the DB is down.

---

## OPTION E — Soft pricing teaser (the reminder from your notes)

> Pricing for Haldir is finally public:
>
>   Free        1k actions/month, 1 agent
>   Pro $99     50k actions/month, 10 agents
>   Enterprise  on-prem, custom
>
> All tiers, same API. Self-host is free forever. haldir.xyz/pricing

(Memo to self: this is the public pricing post you've been sitting on
since 2026-04-14. Send it tonight regardless of which option above you
pick — it's its own tweet.)

---

## Reply playbook (for after the post lands)

People will reply with one of these. Have answers ready.

**"Isn't this just OpenAI evals / LangSmith / Helicone?"**
> Different layer. Those tools observe what happened. Haldir
> intercepts what is about to happen — scope check before the call,
> not telemetry after. The hash chain + signed export is for proving
> what happened to an auditor, not for debugging.

**"Why not just use Pomerium / Cerbos / OPA?"**
> Those are great for service-to-service auth. They do not understand
> "this is an agent session with a $5 spend cap and a 1-hour TTL." The
> session IS the unit of governance, not the request.

**"How is the audit trail actually tamper-evident?"**
> Each entry's SHA-256 hash is computed over the entry contents PLUS
> the previous entry's hash. Edit any historical entry and every later
> hash stops verifying. `haldir audit verify` walks the chain. The
> 0.3.0 export endpoint emits a signed manifest so an offline auditor
> can re-verify after the fact.

**"Is this YC-funded?"**
> No, solo founder, bootstrapping. Looking for 5 design partners and
> first-check seed investors who care about AI infra.

**"Code quality looks suspiciously clean."**
> 310 tests, mypy strict across 18 modules, multi-stage Docker, SBOM.
> Three weeks of hard mode. Look at the bench/ and tests/ directories.

**"Will it survive Hacker News traffic?"**
> Bench shows 1,200 RPS on the write path on a single i3 laptop. The
> hosted instance autoscales. If it doesn't survive I'll learn faster
> than I want to.

---

## Don't do these

- Don't use emojis in any of the above. You stand out without them.
- Don't ask for retweets. Post the screenshot, let the work pull.
- Don't reply to dunks defensively. Quote-and-thank, then walk away.
- Don't post the v0.3.0 tweet AND the pricing tweet in the same hour.
  Stagger by 6 hours minimum so each gets its own engagement window.
- Don't tag VCs. They're lurking; let them DM you.

---

## After-launch checklist

- [ ] PyPI shows 0.3.0 (https://pypi.org/project/haldir/)
- [ ] `pip install --upgrade haldir; haldir overview` works on a fresh
      machine
- [ ] GitHub release attached the wheel + sdist
- [ ] README CLI block is current (it is)
- [ ] Pin the headline tweet to your profile
- [ ] Reply to every reply within 30 min for the first 4 hours
- [ ] Update your X bio to reference v0.3.0 ("shipping Haldir 0.3.0:
      governance for AI agents")
- [ ] DM 5 people in agent infra a personal "would love your eyes on
      this" — not a bulk blast
