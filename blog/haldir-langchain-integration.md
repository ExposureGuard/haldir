# How to Add Governance to LangChain Agents with Haldir

*Published: April 2026 | Tags: LangChain agent security, LangChain governance, AI agent audit trail, LangChain tool permissions*

LangChain is the most popular framework for building AI agents. But LangChain has no built-in governance. Any agent can call any tool, spend any amount, and access any credential. There is no session scoping, no budget enforcement, and no audit trail. When your LangChain agent goes to production, this becomes a liability.

Haldir adds the missing layer. Wrap your LangChain tool calls with Haldir sessions, permission checks, and immutable audit logging. Every tool invocation is authorized, budgeted, and recorded. Here is how.

## The Problem

A typical LangChain agent with tools looks like this:

```python
from langchain.agents import initialize_agent, Tool

tools = [
    Tool(name="search", func=search_api, description="Search the web"),
    Tool(name="send_email", func=send_email, description="Send an email"),
    Tool(name="charge_card", func=charge_card, description="Charge a credit card"),
]

agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
agent.run("Refund the customer $500 and email them confirmation")
```

Nothing stops the agent from calling `charge_card` with the wrong amount. Nothing logs what happened. Nothing enforces a budget. If the LLM hallucinates a $5,000 charge, it goes through.

## The Solution: Haldir-Wrapped Tools

Create a wrapper that routes every tool call through Haldir. Each call is checked against session scopes, logged to the audit trail, and tracked for spend.

```python
from haldir import HaldirClient, HaldirPermissionError
from langchain.agents import initialize_agent, Tool

h = HaldirClient(api_key="hld_xxx")

# Create a scoped session for this agent run
session = h.create_session(
    agent_id="customer-service-bot",
    scopes=["read", "send_email", "spend:100"],
    spend_limit=100.00,
    ttl=1800
)
sid = session["session_id"]


def governed_tool(name, func, scope, cost_usd=0.0):
    """Wrap a LangChain tool function with Haldir governance."""
    def wrapper(*args, **kwargs):
        # Check permission before executing
        check = h.check_permission(sid, scope)
        if not check["allowed"]:
            return f"BLOCKED: Agent does not have '{scope}' permission."

        # If this costs money, authorize the spend first
        if cost_usd > 0:
            h.authorize_payment(sid, amount=cost_usd, description=f"{name}: {args}")

        # Execute the actual tool
        result = func(*args, **kwargs)

        # Log the action to the immutable audit trail
        h.log_action(sid, tool=name, action="execute", cost_usd=cost_usd,
                      details={"args": str(args), "result_preview": str(result)[:200]})
        return result

    return wrapper


# Wrap each tool with governance
tools = [
    Tool(
        name="search",
        func=governed_tool("search", search_api, scope="read"),
        description="Search the web"
    ),
    Tool(
        name="send_email",
        func=governed_tool("send_email", send_email, scope="send_email"),
        description="Send an email to a customer"
    ),
    Tool(
        name="charge_card",
        func=governed_tool("charge_card", charge_card, scope="spend", cost_usd=50.0),
        description="Charge a credit card"
    ),
]

agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
```

Now every tool call goes through Haldir. The agent can search freely (it has the `read` scope), send emails (it has `send_email`), and charge up to $100 total (its spend limit). If the LLM tries to call a tool outside its scopes, the call is blocked before it executes.

## Handling Permission Denials Gracefully

When a tool is blocked, the agent receives the denial as a tool response. LangChain agents handle this naturally by trying a different approach or reporting the limitation to the user:

```python
def governed_tool(name, func, scope, cost_usd=0.0):
    def wrapper(*args, **kwargs):
        try:
            check = h.check_permission(sid, scope)
            if not check["allowed"]:
                return f"Permission denied: '{scope}' not in session scopes."

            if cost_usd > 0:
                h.authorize_payment(sid, amount=cost_usd, description=name)

            result = func(*args, **kwargs)
            h.log_action(sid, tool=name, action="execute", cost_usd=cost_usd)
            return result

        except HaldirPermissionError as e:
            h.log_action(sid, tool=name, action="blocked", details={"reason": str(e)})
            return f"Budget exceeded or permission denied: {e}"

    return wrapper
```

The agent receives "Budget exceeded" as a tool output and can inform the user instead of failing silently.

## Reviewing What Your Agent Did

After the agent run completes, pull the full audit trail:

```python
# Get everything this session did
trail = h.get_audit_trail(session_id=sid)
for entry in trail["entries"]:
    print(f"{entry['timestamp']} | {entry['tool']} | {entry['action']} | ${entry['cost_usd']}")

# Check total spend
spend = h.get_spend(session_id=sid)
print(f"Total spend: ${spend['total_usd']:.2f}")

# Revoke the session when the agent is done
h.revoke_session(sid)
```

Output:

```
2026-04-05T14:30:01Z | search      | execute | $0.00
2026-04-05T14:30:03Z | send_email  | execute | $0.00
2026-04-05T14:30:05Z | charge_card | execute | $50.00
Total spend: $50.00
```

Every action is recorded with the session ID, agent ID, timestamp, tool name, and cost. This is the compliance record that enterprise teams require before deploying agents.

## Vault Integration for Secrets

Store your API keys in Haldir Vault instead of environment variables. The agent only accesses credentials through scoped sessions:

```python
# Store secrets once (admin setup)
h.store_secret("stripe_key", "sk_live_xxx", scope_required="spend")
h.store_secret("sendgrid_key", "SG.xxx", scope_required="send_email")

# Agent retrieves secrets through its session — scope is enforced
stripe_key = h.get_secret("stripe_key", session_id=sid)
```

If the session does not have the `spend` scope, the secret retrieval is denied. No more plaintext keys in `.env` files.

## Getting Started

```bash
pip install haldir langchain
```

Create a session, wrap your tools, and run your agent. Five lines of code between "no governance" and "full audit trail with budget enforcement."

Docs: [haldir.xyz/docs](https://haldir.xyz/docs) | Source: [GitHub](https://github.com/ExposureGuard/haldir)

---

*Haldir is the governance layer for AI agents. Session scoping, spend limits, encrypted secrets, and immutable audit trails. Works with LangChain, CrewAI, AutoGen, or any framework. Start free at [haldir.xyz](https://haldir.xyz).*
