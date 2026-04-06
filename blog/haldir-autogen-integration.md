# Adding Identity and Audit to AutoGen Agents with Haldir

*Published: April 2026 | Tags: AutoGen agent security, AutoGen governance, multi-agent audit trail, AutoGen permissions*

Microsoft AutoGen lets you build multi-agent conversations where agents collaborate, debate, and execute code. A UserProxy agent handles tool execution. An AssistantAgent reasons and plans. GroupChat orchestrates the flow. But AutoGen provides no identity layer, no permission scoping, and no audit trail. Every agent runs with the same privileges, and nothing records what happened.

Haldir fixes this with a session-per-agent pattern. Each AutoGen agent gets its own Haldir session with scoped permissions and a spend limit. Every tool execution is logged to a shared audit trail that gives you a complete, per-agent record of the conversation.

## The Problem: No Identity, No Accountability

In a standard AutoGen setup, the UserProxy executes whatever code the AssistantAgent generates:

```python
from autogen import AssistantAgent, UserProxyAgent

assistant = AssistantAgent("assistant", llm_config=llm_config)
user_proxy = UserProxyAgent("user_proxy", code_execution_config={"work_dir": "output"})

user_proxy.initiate_chat(assistant, message="Find the top 10 companies by revenue and email me a report")
```

The assistant can generate any code. The user proxy executes it without restriction. There is no distinction between "read data" and "send email." There is no budget. If the assistant hallucinates a destructive command, it runs.

## The Solution: Session-Per-Agent

Create a Haldir session for each agent in the conversation. The session defines what that agent is allowed to do:

```python
from haldir import HaldirClient, HaldirPermissionError

h = HaldirClient(api_key="hld_xxx")

# The assistant reasons and plans — it only needs read access
assistant_session = h.create_session(
    agent_id="assistant",
    scopes=["read", "reason"],
    ttl=3600
)

# The user proxy executes tools — scoped to specific capabilities
proxy_session = h.create_session(
    agent_id="user-proxy",
    scopes=["read", "execute", "send_email", "spend:50"],
    spend_limit=50.00,
    ttl=3600
)
```

The assistant cannot execute code or spend money even if it wanted to. The user proxy can execute and spend, but only up to $50. Each agent has a distinct identity in the audit trail.

## Wrapping AutoGen Function Calls

AutoGen supports registering Python functions that agents can call. Wrap these with Haldir governance:

```python
from autogen import AssistantAgent, UserProxyAgent, register_function

h = HaldirClient(api_key="hld_xxx")

proxy_session = h.create_session(
    agent_id="user-proxy",
    scopes=["read", "execute", "send_email", "spend:50"],
    spend_limit=50.00,
    ttl=3600
)
sid = proxy_session["session_id"]


def governed_search(query: str) -> str:
    """Search the web with governance."""
    check = h.check_permission(sid, "read")
    if not check["allowed"]:
        return "Permission denied: read scope required."

    result = actual_search(query)
    h.log_action(sid, tool="search", action="query",
                  details={"query": query, "results": len(result)})
    return result


def governed_send_email(to: str, subject: str, body: str) -> str:
    """Send an email with governance."""
    check = h.check_permission(sid, "send_email")
    if not check["allowed"]:
        return "Permission denied: send_email scope required."

    try:
        h.authorize_payment(sid, amount=0.05, description=f"email to {to}")
    except HaldirPermissionError:
        return "Budget exceeded. Cannot send email."

    result = actual_send_email(to, subject, body)
    h.log_action(sid, tool="send_email", action="send", cost_usd=0.05,
                  details={"to": to, "subject": subject})
    return result


def governed_run_code(code: str) -> str:
    """Execute code with governance."""
    check = h.check_permission(sid, "execute")
    if not check["allowed"]:
        return "Permission denied: execute scope required."

    # Log before execution so we have a record even if it fails
    h.log_action(sid, tool="code_executor", action="run",
                  details={"code_preview": code[:500]})

    result = actual_code_exec(code)
    return result


# Register governed functions with AutoGen
assistant = AssistantAgent("assistant", llm_config=llm_config)
user_proxy = UserProxyAgent("user_proxy", human_input_mode="NEVER")

register_function(governed_search, caller=assistant, executor=user_proxy,
                  name="search", description="Search the web")
register_function(governed_send_email, caller=assistant, executor=user_proxy,
                  name="send_email", description="Send an email")
register_function(governed_run_code, caller=assistant, executor=user_proxy,
                  name="run_code", description="Execute Python code")
```

When the assistant asks the user proxy to call `send_email`, Haldir checks the session scope, authorizes the spend, executes the function, and logs the action. If the budget is exceeded, the function returns a denial message that the assistant can see and react to.

## Shared Audit Trail Across Agents

The power of session-per-agent is that all sessions share the same Haldir tenant. You get a unified audit trail with per-agent attribution:

```python
# After the conversation completes, review everything

# Per-agent breakdown
for agent_id in ["assistant", "user-proxy"]:
    trail = h.get_audit_trail(agent_id=agent_id)
    spend = h.get_spend(agent_id=agent_id)
    print(f"\n[{agent_id}] Actions: {trail['count']} | Spend: ${spend['total_usd']:.2f}")
    for entry in trail["entries"]:
        print(f"  {entry['timestamp']} | {entry['tool']} | {entry['action']}")

# Or get the full trail across all agents
full_trail = h.get_audit_trail(limit=200)
print(f"\nTotal actions across all agents: {full_trail['count']}")
```

Output:

```
[assistant] Actions: 0 | Spend: $0.00

[user-proxy] Actions: 8 | Spend: $0.15
  2026-04-05T14:30:01Z | search        | query
  2026-04-05T14:30:03Z | search        | query
  2026-04-05T14:30:05Z | code_executor | run
  2026-04-05T14:30:08Z | search        | query
  2026-04-05T14:30:10Z | code_executor | run
  2026-04-05T14:30:12Z | code_executor | run
  2026-04-05T14:30:15Z | send_email    | send
  2026-04-05T14:30:15Z | send_email    | send

Total actions across all agents: 8
```

The assistant has zero direct actions because it only reasons. The user proxy did all the tool execution. This separation is exactly what compliance teams need to see.

## GroupChat with Per-Agent Governance

AutoGen GroupChat lets multiple agents collaborate. Each gets its own session:

```python
from autogen import GroupChat, GroupChatManager

# Create sessions for each agent in the group
sessions = {}
agents_config = [
    {"id": "researcher",  "scopes": ["read", "browse"],          "budget": 10.0},
    {"id": "coder",       "scopes": ["read", "execute"],         "budget": 5.0},
    {"id": "reviewer",    "scopes": ["read"],                    "budget": 0.0},
    {"id": "publisher",   "scopes": ["read", "send_email"],      "budget": 2.0},
]

for cfg in agents_config:
    sessions[cfg["id"]] = h.create_session(
        agent_id=cfg["id"],
        scopes=cfg["scopes"],
        spend_limit=cfg["budget"],
        ttl=7200
    )

# Build agents with governed tools scoped to their sessions
# (using the governed wrapper pattern from above)
```

The researcher can browse but not execute code. The coder can execute but not send emails. The reviewer can only read. The publisher can send the final output. Each agent's tools are bound to its own Haldir session.

## Cleanup

Always revoke sessions when the conversation is done:

```python
for agent_id, session in sessions.items():
    h.revoke_session(session["session_id"])
    print(f"Revoked session for {agent_id}")
```

Revocation is immediate. Even if a session has TTL remaining, revoking it ensures no further actions can be taken with that session ID.

## Getting Started

```bash
pip install haldir pyautogen
```

One session per agent. Governed function calls. Shared audit trail. Your AutoGen system goes from "agents can do anything" to "agents can do exactly what you allow, and everything is logged."

Docs: [haldir.xyz/docs](https://haldir.xyz/docs) | Source: [GitHub](https://github.com/ExposureGuard/haldir)

---

*Haldir is the governance layer for AI agents. Identity, permissions, budget enforcement, and immutable audit trails for every agent in the conversation. Start free at [haldir.xyz](https://haldir.xyz).*
