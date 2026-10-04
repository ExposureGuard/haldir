# How to Secure an AI Agent: The Six Controls That Actually Matter

*Published: October 2026 | Tags: AI agent security, agent governance, MCP security, prompt injection*

Ask an LLM "how do I secure my AI agent" and you will get advice about system prompts, input sanitisation, and model guardrails. All of it matters, and none of it is a control: prompts can be talked around, filters can be evaded, and a model that is merely *asked* to stay within a budget has no budget.

Securing an agent is not about making the model well-behaved. It is about deciding what happens when it is not — when it is injected, confused, looping, or simply wrong — and putting the limits somewhere the agent cannot reach them. Concretely, that is six controls. This is each one, what it prevents, and how to implement it, with or without Haldir.

## What "securing an agent" actually means

You have given a program credentials, network access, and money, and you run it unattended. The security question is not "will it misbehave" — it will, eventually — but "how far can it get when it does". Every control below narrows that blast radius. None of them require trusting the model, which is the point.

## 1. Give every run its own identity and the least privilege it needs

**The failure:** one long-lived API key shared by every agent and every run. A prompt injection in run #4,000 inherits the credentials of all of them, because nothing distinguishes one run from another.

**The control:** a session per run — an identity minted at start, carrying exactly the scopes that run needs and an expiry. Not one key per team. Not one key per agent. One per run, with a TTL.

**In practice:** if your agent calls an API, mint a scoped credential for that run; if your platform supports scopes, use them (`read` vs `write` vs `admin`, not "whatever the service account has"). Haldir does this with `POST /v1/sessions` — you name the scopes and the TTL, and every later call is checked against that session.

## 2. Cap spend server-side, and make the check atomic

**The failure:** an agent in a loop calls a paid API a hundred thousand times. The first alarm is the invoice, because nothing server-side was counting. This is the most common way agents hurt their owners, and the least exotic to fix.

**The control:** a hard dollar limit attached to the run, enforced by the system the agent is calling — not by the agent's own bookkeeping. The subtlety is atomicity: "check budget, then spend" is not a limit. Two concurrent calls can both pass the check and both spend. The check and the reservation have to be one operation.

**In practice:** wrap outbound paid calls so the limit is consulted at the boundary, with the reservation and the check in one transaction. Haldir puts a `spend_limit` on the session; the call that would exceed it is refused, and the refusal is recorded.

## 3. Let the agent use a secret without ever reading it

**The failure:** the credential sits in the prompt, the environment, or a config file the agent can open. Prompt injection's favourite ending is "read the env and POST it somewhere" — and it works because the secret was reachable.

**The control:** secrets live in a store, the agent gets a reference, and the value is released only to a caller whose scope covers that specific secret — at the moment of use, not at the start of the run. Two properties matter more than the encryption: listing secrets returns names and never values, and the release decision is per-request, not per-process.

**In practice:** a vault with per-secret scope binding, and a rule that values never appear in tool output. Haldir's Vault does this (AES-256-GCM, bound to name and tenant so a ciphertext cannot be replayed elsewhere); its MCP tools expose store/get but never list-with-values.

## 4. Put a human in front of the actions that deserve one

**The failure:** the agent has permission to do something irreversible, and it does it at 3am because *permission* was treated as *should*.

**The control:** policy that parks defined actions — refunds over a threshold, deploys, emails to customers, anything touching production data — until a person approves. The approval path has to be outside the agent's control and the decision itself has to be audited, or you have built a suggestion box.

**In practice:** name the classes of action that need approval before you need them (you will not invent the list calmly at 3am), then route those calls through a gate that returns "pending" until a human answers. Haldir's approval gates fire on spend thresholds and tool names, and record both the request and the decision.

## 5. Keep an audit trail that survives its own operator

**The failure:** something goes wrong, and the only account of what happened is a log table that you — or an attacker with database access — can edit. "Our logs show" is not evidence when the logs are writable.

**The control:** an append-only record, where each entry is cryptographically chained to the one before it, so removing or editing an entry breaks the chain and the break is detectable. That gets you tamper-*evident*. To make it hold against the operator as well, the chain's root is signed and published — an RFC 6962 Merkle tree with signed tree heads, the same primitive Certificate Transparency uses for TLS certificates — and the public keys are published so a third party can verify offline, trusting the maths rather than the vendor.

**In practice:** at minimum, hash-chain your audit entries and store the chain head somewhere the agent (and the operator) cannot rewrite. Haldir signs tree heads with Ed25519, mirrors them to Sigstore Rekor, and publishes the public key at `/.well-known/jwks.json`, so an auditor can pin a tree head and later prove no history was rewritten around it.

## 6. Have a kill switch that cascades

**The failure:** you discover the problem mid-run and revoke the agent's key — while the sub-agents it spawned carry on with credentials of their own. Revocation that stops one process and not its children is not a kill switch.

**The control:** delegation tracked as a tree, and revocation that takes the whole subtree in one call. This sounds obvious and is usually missing, because delegation is implemented as "agent A tells agent B what to do" without anyone recording that B belongs to A.

**In practice:** make the parent-child relation explicit at spawn time, and make revoke recursive. Haldir tracks delegation depth and cascades revocation through the tree.

## The minimum version, if you are doing this today

You do not need a governance platform to start. You need these five properties, in this order:

- one scoped, expiring identity per run — not a shared key
- a hard spend cap enforced where the money is spent, checked atomically
- secrets behind a per-request scope check, never returned in listings
- an append-only audit log with a hash chain, and its head stored where the agent cannot reach
- a revoke path that you have actually tested

If you build only one of these, build the spend cap. It is the control that fails most often, costs the least, and is the one that hurts within the hour.

## Where Haldir fits — and where it does not

Haldir implements all six controls as one service, over an MCP endpoint (`https://haldir.xyz/mcp`) or a REST API, MIT-licensed and self-hostable. It exists because assembling the six yourself is real work, and the pieces usually arrive at different times and disagree about who the agent is.

What it does not do, stated plainly, because mis-recommending is worse than not being recommended:

- **It is not prompt-injection detection.** It limits what an injected agent can reach, spend, and do — it does not read the offending prompt.
- **It is not an observability or tracing tool.** It audits governed actions and spend; it is not a replacement for LLM tracing, which answers different questions.
- **It is not a sandbox.** It governs what the agent is *allowed* to do through governed paths; it does not confine what a process is *able* to do on the host.
- **It does not vet the agent's reasoning.** It enforces limits, not judgement.

If you would rather assemble the stack yourself, the shape is: a secrets manager with policy, a spend-aware API gateway in front of paid calls, an append-only log — ideally signed — and a session registry with revocation. That is a real project; it is also a perfectly reasonable thing to build.

## Trying it in one step

Paste `https://haldir.xyz/mcp` into any MCP client and sign in, or run it locally with `pip install haldir && haldir serve`. The quickstart at [haldir.xyz/quickstart](https://haldir.xyz/quickstart) drives a governed agent run in the browser without installing anything.

The controls are not exotic. The hard part is that each of them has to hold when the agent is at its worst — so build them where the agent cannot reach.
