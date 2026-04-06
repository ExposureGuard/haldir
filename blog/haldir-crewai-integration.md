# Securing CrewAI Multi-Agent Systems with Haldir

*Published: April 2026 | Tags: CrewAI security, multi-agent governance, AI agent budget enforcement, CrewAI permissions*

CrewAI makes it easy to orchestrate multiple AI agents working together. A researcher agent gathers data. An analyst agent processes it. A writer agent produces the report. But CrewAI has no built-in mechanism for scoping what each agent can do, enforcing budgets across the crew, or producing an audit trail of who did what.

When your crew has access to real tools that cost money, send emails, or modify databases, you need governance. Haldir gives each CrewAI agent its own scoped session with independent permissions, budget limits, and audit logging. Here is how to wire it up.

## The Problem: Flat Permissions Across Agents

In a default CrewAI setup, every agent in the crew has equal access to every tool:

```python
from crewai import Agent, Task, Crew

researcher = Agent(role="Researcher", tools=[search, scrape, api_call])
analyst = Agent(role="Analyst", tools=[search, scrape, api_call, database_write])
writer = Agent(role="Writer", tools=[search, scrape, api_call, send_email])

crew = Crew(agents=[researcher, analyst, writer], tasks=[...])
crew.kickoff()
```

The researcher can write to the database. The analyst can send emails. Every agent can make unlimited API calls. There is no separation of concerns, no budget tracking, and no record of which agent performed which action.

## The Solution: One Haldir Session Per Agent

Create a separate Haldir session for each CrewAI agent. Each session has its own scopes, spend limit, and TTL. Actions are logged per session, giving you a per-agent audit trail.

```python
from haldir import HaldirClient, HaldirPermissionError
from crewai import Agent, Task, Crew

h = HaldirClient(api_key="hld_xxx")

# Each agent gets its own scoped session
researcher_session = h.create_session(
    agent_id="researcher",
    scopes=["read", "browse"],
    spend_limit=5.00,
    ttl=3600
)

analyst_session = h.create_session(
    agent_id="analyst",
    scopes=["read", "db_write"],
    spend_limit=10.00,
    ttl=3600
)

writer_session = h.create_session(
    agent_id="writer",
    scopes=["read", "send_email"],
    spend_limit=2.00,
    ttl=3600
)
```

The researcher can browse and read, but cannot write to the database or send emails. The analyst can write to the database but cannot send emails. The writer can send emails but cannot touch the database. Each has an independent budget.

## Building Governed Tool Wrappers

Create a factory that produces governed versions of your tools, scoped to a specific session:

```python
def make_governed_tools(session, tools_config):
    """Create governed tool functions bound to a Haldir session."""
    sid = session["session_id"]
    governed = []

    for config in tools_config:
        name = config["name"]
        func = config["func"]
        scope = config["scope"]
        cost = config.get("cost_usd", 0.0)

        def _make_wrapper(n, f, sc, c):
            def wrapper(*args, **kwargs):
                # Permission check
                check = h.check_permission(sid, sc)
                if not check["allowed"]:
                    return f"BLOCKED: {n} requires '{sc}' scope."

                # Budget check for paid operations
                if c > 0:
                    try:
                        h.authorize_payment(sid, amount=c, description=n)
                    except HaldirPermissionError:
                        return f"BUDGET EXCEEDED: {n} costs ${c:.2f}, limit reached."

                # Execute and log
                result = f(*args, **kwargs)
                h.log_action(sid, tool=n, action="execute", cost_usd=c)
                return result
            return wrapper

        governed.append({
            "name": name,
            "func": _make_wrapper(name, func, scope, cost),
            "description": config.get("description", ""),
        })

    return governed
```

Now create agents with their governed tools:

```python
researcher_tools = make_governed_tools(researcher_session, [
    {"name": "search", "func": search_api, "scope": "read",
     "description": "Search the web"},
    {"name": "scrape", "func": scrape_url, "scope": "browse",
     "description": "Scrape a webpage", "cost_usd": 0.01},
])

analyst_tools = make_governed_tools(analyst_session, [
    {"name": "search", "func": search_api, "scope": "read",
     "description": "Search the web"},
    {"name": "db_write", "func": write_to_db, "scope": "db_write",
     "description": "Write analysis results to database"},
])

writer_tools = make_governed_tools(writer_session, [
    {"name": "search", "func": search_api, "scope": "read",
     "description": "Search the web"},
    {"name": "send_email", "func": send_email, "scope": "send_email",
     "description": "Send the final report via email", "cost_usd": 0.05},
])
```

## Budget Enforcement Across the Crew

Haldir tracks spend per session and per agent. You can set a global crew budget by checking aggregate spend before each task:

```python
CREW_BUDGET = 15.00  # Total budget for the entire crew run

def check_crew_budget():
    """Check if the crew has exceeded its total budget."""
    researcher_spend = h.get_spend(session_id=researcher_session["session_id"])
    analyst_spend = h.get_spend(session_id=analyst_session["session_id"])
    writer_spend = h.get_spend(session_id=writer_session["session_id"])

    total = (researcher_spend["total_usd"]
             + analyst_spend["total_usd"]
             + writer_spend["total_usd"])

    if total >= CREW_BUDGET:
        raise RuntimeError(f"Crew budget exhausted: ${total:.2f} / ${CREW_BUDGET:.2f}")

    return total
```

Call `check_crew_budget()` between tasks or inside a CrewAI callback. If the crew exceeds its budget, execution stops before more money is spent.

## Per-Agent Audit Trail

After the crew finishes, pull each agent's audit trail independently:

```python
sessions = {
    "researcher": researcher_session,
    "analyst": analyst_session,
    "writer": writer_session,
}

for name, session in sessions.items():
    trail = h.get_audit_trail(session_id=session["session_id"])
    spend = h.get_spend(session_id=session["session_id"])

    print(f"\n--- {name} ---")
    print(f"Actions: {trail['count']}")
    print(f"Spend: ${spend['total_usd']:.2f}")

    for entry in trail["entries"]:
        status = "BLOCKED" if entry.get("flagged") else "OK"
        print(f"  {entry['timestamp']} | {entry['tool']} | {status} | ${entry['cost_usd']}")

    # Revoke session when done
    h.revoke_session(session["session_id"])
```

Output:

```
--- researcher ---
Actions: 12
Spend: $0.10
  2026-04-05T14:30:01Z | search  | OK | $0.00
  2026-04-05T14:30:02Z | scrape  | OK | $0.01
  ...

--- analyst ---
Actions: 5
Spend: $0.00
  2026-04-05T14:31:01Z | search   | OK | $0.00
  2026-04-05T14:31:04Z | db_write | OK | $0.00

--- writer ---
Actions: 3
Spend: $0.05
  2026-04-05T14:32:01Z | search     | OK | $0.00
  2026-04-05T14:32:05Z | send_email | OK | $0.05
```

You know exactly what each agent did, how much it spent, and whether any actions were blocked. This is the per-agent accountability that production multi-agent systems require.

## Secrets Isolation

Use Haldir Vault to give each agent access only to the credentials it needs:

```python
# Store secrets with scope requirements
h.store_secret("search_api_key", "sk_xxx", scope_required="read")
h.store_secret("db_password", "pg_xxx", scope_required="db_write")
h.store_secret("smtp_key", "SG_xxx", scope_required="send_email")

# Researcher can access search_api_key but NOT db_password or smtp_key
key = h.get_secret("search_api_key", session_id=researcher_session["session_id"])  # Works
key = h.get_secret("db_password", session_id=researcher_session["session_id"])     # Denied
```

Each agent sees only the secrets its session scopes allow. No cross-agent credential leakage.

## Getting Started

```bash
pip install haldir crewai
```

One session per agent. Scoped permissions. Budget enforcement. Full audit trail. Your CrewAI system goes from "hope nothing breaks" to "verifiable governance" in under 50 lines.

Docs: [haldir.xyz/docs](https://haldir.xyz/docs) | Source: [GitHub](https://github.com/ExposureGuard/haldir)

---

*Haldir is the governance layer for AI agents. Session scoping, spend limits, encrypted secrets, and immutable audit trails for every agent in your crew. Start free at [haldir.xyz](https://haldir.xyz).*
