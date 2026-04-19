# Prospect playbook — enterprise security engineers

For when a Big-4 / enterprise security engineer engages publicly with
Haldir on X, LinkedIn, or in a community forum. Generalized from the
2026-04-19 Touseef Hussain (Deloitte) engagement.

> **Why this persona matters disproportionately:** a single security
> engineer at Deloitte / PwC / EY / KPMG (or in-house at any Fortune
> 500) shapes what their firm recommends to dozens of enterprise
> clients on AI governance. Even if they personally never deploy
> Haldir, becoming the founder they name-drop in their internal AI
> Governance Working Group is worth more than 100 GitHub stars.

---

## 1. Triage — within 30 minutes of their public engagement

Confirm the persona before investing time:

- **Title:** Security engineer / Security architect / GRC analyst /
  Cyber risk consultant / SOC2 auditor.
- **Employer:** Big 4, Fortune 500, well-known security boutique
  (Bishop Fox, NCC, Praetorian), or compliance vendor (Vanta, Drata,
  Secureframe, Anecdotes).
- **Public reply quality:** asked a question, didn't dunk. Genuine
  curiosity, not gotcha.

If all three boxes check → DM within the next hour.

---

## 2. The first DM (X or LinkedIn — wherever they're more active)

Lead with their expertise, not your product. Drop a SOC2 control code
or two so they know you're serious. Make the ask low-effort (20 min,
not 60). End warmly.

```
Hey <Name> — appreciated the question on the launch. Quick intro:
Sterling, solo founder of Haldir.

Your background caught my eye — <their role> at <their employer>
means you've probably seen agent governance gaps from inside
Fortune-class engagements. Genuinely curious: what's the gap you're
seeing most in client AI deployments right now? I'm taking notes
from people I trust over building features in a vacuum.

Separately: we shipped a compliance evidence pack today —
auditor-ready proof-of-control document, signed, SOC2-mapped (CC6.1,
CC6.7, CC7.2, CC8.1). Would love a security engineer's eyes on it.
Happy to walk through it in 20 min and hear what's missing. Sandbox
+ design partner spot on the table if it's useful.

Either way — thanks for engaging publicly. Few do.
```

**What to vary:** the SOC2 codes (pick the ones their firm specializes
in). Drop the design partner offer entirely if they're at a vendor
(Vanta, Drata) — they're competitive context, not customer.

---

## 3. The 20-minute walkthrough — if they say yes

Total run time: 20 minutes. Hard stop. Respect their time and they
remember you for the right reasons.

| Min | What you're doing | Why |
|-----|-------------------|-----|
| 0-2 | "Tell me what your typical AI engagement looks like — auditing existing deployments, advising on new ones, building reference architectures?" | Learning their world. They feel heard. |
| 2-7 | Run `haldir overview` against a sandbox. CLI dashboard. Pause on the audit row + chain-verified checkmark. | Shows the platform's range in 30 seconds. |
| 7-15 | Run `haldir compliance evidence --format markdown --out evidence.md` against the sandbox. Open the .md in a viewer. Walk through each SOC2 section. **Ask: "If a client handed you this in a SOC2 audit prep meeting, what would you mark missing?"** Let them roast it. Take notes. | This is the gold. The roast IS the value. |
| 15-18 | Show `haldir audit verify` (chain integrity) + the signed manifest + re-verification flow. | Closes the "is this just JSON in Postgres" objection. |
| 18-20 | "What would Deloitte clients actually pay for this kind of artifact? What's the price-anchoring number you've heard?" | Market intel they can give freely. Pricing signal you can't get any other way. |

**Don't ask them to recommend you.** Ask for the gaps. The
recommendation comes later if the product is good enough.

---

## 4. If they ghost the DM

Wait 4 calendar days. Send exactly ONE follow-up:

```
<Name> — quick follow-up. Wanted to share: we have a public sandbox
now where you can mint a key and pull a real evidence pack in 30
seconds:

  haldir.xyz/admin/overview?demo=1
  haldir compliance evidence --format md

No need to set up a call. If you take it for a spin and have 60
seconds to share what's missing, I'd be grateful.
```

Then drop it. Don't third-touch.

---

## 5. The compounding move — do this regardless of their first response

Investments that pay off in 6-12 months even if the first call goes
nowhere:

- **Follow them.** Bookmark profile.
- **Reply substantively to 2-3 of their next posts** over the
  following 2 weeks. Not on Haldir — on their actual interests
  (agent security, compliance, threat modeling). Show you read.
- **Quote-tweet their AI governance takes** with your own additive
  perspective.
- **When their firm runs an internal AI Governance Working Group**
  (it will — every Big 4 has one), you want them to remember Haldir
  unprompted.

The conversion path here is months long. The competing product they're
recommending today is whatever they remember from the last conversation
they had with a competent founder. Keep being that conversation.

---

## 6. Worked example — Touseef Hussain, security engineer @ Deloitte

- **2026-04-19 10:03 ET:** replied publicly on the v0.3.0 launch
  thread asking when to use Haldir.
- **2026-04-19 ~12:00 ET:** Sterling replied publicly + sent the DM
  template above.
- **Status:** awaiting response.
- **Why this contact matters:** Deloitte audits the AI deployments
  of every Fortune 100 financial services firm. Their AI Risk &
  Cybersecurity practice is publishing reference frameworks for
  agent governance in 2026. A Deloitte security engineer who
  champions Haldir is a direct line into procurement at every
  bank, insurer, and asset manager engaged with Deloitte
  Consulting.

Update this section with each new interaction so the next outreach
references prior context.

---

## 7. Anti-patterns — never do these

- **Don't ask for upvotes / retweets.** Looks desperate. Even
  worse from a security engineer who notices.
- **Don't pitch "we have AES-256!" to a security engineer.**
  They've seen it. Pitch the differentiator: hash-chained audit,
  signed evidence pack, scope-restricted keys.
- **Don't name-drop their firm in your founder narrative ("Haldir
  is talking to Deloitte!"). They will see it and ghost.** Conversations
  are private until they say otherwise.
- **Don't respond with marketing speak.** They detect it instantly.
  Be specific, technical, modest.
- **Don't follow up more than twice.** First DM, one nudge if no
  response, then nothing. They will remember a polite founder
  far longer than a persistent one.
