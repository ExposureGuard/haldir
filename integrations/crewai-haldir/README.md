# crewai-haldir

Governance layer for CrewAI agents — audit trails, spend caps, secrets vault, and instant revocation.

Wrap any CrewAI tool in Haldir's enforcement proxy so every tool call is scope-checked, cost-tracked, and logged to a tamper-evident audit trail.

## Install

```bash
pip install crewai-haldir
```

You'll need a Haldir API key. Create one free at [haldir.xyz](https://haldir.xyz).

## 30-second quickstart

```python
from crewai import Agent, Task, Crew
from crewai_tools import SerperDevTool
from crewai_haldir import create_session, GovernedTool

# Create a scoped Haldir session with a $10 spend cap
client, session_id = create_session(
    api_key="hld_xxx",
    agent_id="research-crew",
    scopes=["read", "search", "spend"],
    spend_limit=10.0,
)

# Wrap your tools so Haldir enforces permissions
search = GovernedTool.wrap(
    SerperDevTool(),
    client=client,
    session_id=session_id,
    required_scope="search",
    cost_usd=0.01,
)

# Build your crew as usual — governance happens transparently
researcher = Agent(
    role="Senior Research Analyst",
    goal="Find the most recent news on a topic",
    backstory="A diligent researcher with attention to sources.",
    tools=[search],
)

task = Task(
    description="Find the latest news about AI agent security incidents.",
    expected_output="A bulleted list with sources.",
    agent=researcher,
)

crew = Crew(agents=[researcher], tasks=[task])
crew.kickoff()
```

Every tool call is now:
- **Permission-checked** before execution (revoked or out-of-scope sessions raise `HaldirPermissionError`)
- **Cost-tracked** against the session's `spend_limit`
- **Logged** to Haldir's hash-chained audit trail with tool name, timestamp, and cost

## Secrets without leaking them to the model

```python
from crewai_haldir import HaldirSecrets

# Store the secret once (out-of-band, not from the agent):
# client.store_secret("serper_api_key", "sk_xxx", scope_required="search")

secrets = HaldirSecrets(client, session_id)
serper_key = secrets.get("serper_api_key")  # SecretStr — masked in logs

# Use in your tool configuration — raw value never enters an LLM prompt
import os
os.environ["SERPER_API_KEY"] = serper_key.get_secret_value()
```

If the session's scopes don't include the required scope, `secrets.get()` raises `HaldirPermissionError`.

## Revoking a crew mid-run

Any process with the Haldir API key can revoke the session — execution halts on the next tool call.

```python
client.revoke_session(session_id)  # next tool call → HaldirPermissionError
```

This gives you a kill switch over any running crew.

## Variable-cost tools

For tools where cost varies per call (e.g. LLM inference, paid APIs), pass `cost_fn`:

```python
def web_scraper_cost(result):
    # Charge per thousand characters returned
    return len(str(result)) / 1000 * 0.005

scraper = GovernedTool.wrap(
    WebScraperTool(),
    client=client,
    session_id=session_id,
    required_scope="read",
    cost_fn=web_scraper_cost,
)
```

## Scope patterns

Different tools, different scopes — the session's scope list must include all of them:

```python
scopes = ["read", "search", "execute", "spend"]

search_tool   = GovernedTool.wrap(SerperDevTool(),   client, session_id, required_scope="search")
code_tool     = GovernedTool.wrap(PythonREPLTool(),  client, session_id, required_scope="execute")
payment_tool  = GovernedTool.wrap(StripeTool(),      client, session_id, required_scope="spend")
```

Revoke the session entirely at runtime — the next tool call will fail:

```python
client.revoke_session(session_id)  # next tool call → HaldirPermissionError
```

## API

- `create_session(api_key, agent_id, scopes, ttl, spend_limit, base_url) -> (client, session_id)`
- `GovernedTool.wrap(tool, client, session_id, required_scope, cost_usd, cost_fn) -> GovernedTool`
- `HaldirSecrets(client, session_id).get(name) -> SecretStr`

## Links

- Haldir: [haldir.xyz](https://haldir.xyz)
- Haldir docs: [haldir.xyz/docs](https://haldir.xyz/docs)
- Source: [github.com/ExposureGuard/haldir](https://github.com/ExposureGuard/haldir/tree/main/integrations/crewai-haldir)
- Sibling packages: [langchain-haldir](https://pypi.org/project/langchain-haldir/)

## License

MIT
