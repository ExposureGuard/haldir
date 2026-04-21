# crewai-haldir

Cryptographic-audit + governance for CrewAI agents. Two lines of code.

- **Audit trail** — every tool call logged to a SHA-256 hash-chained + RFC 6962 Merkle-covered audit log
- **Scope enforcement** — denied tools abort with `HaldirPermissionError`
- **Secrets vault** — scope-checked credential retrieval as `SecretStr`
- **Tree-head stamping** — attach the current Signed Tree Head to the crew's output; pin for offline verification later
- **Instant revocation** — any process can revoke a session mid-run; next tool call aborts
- **Auto-lifecycle** — session minted on `with` entry, revoked on exit even if the crew raises

## Install

```bash
pip install crewai-haldir
```

Free Haldir API key at [haldir.xyz](https://haldir.xyz).

## Two-line quickstart

```python
from crewai import Agent, Task, Crew
from crewai_tools import SerperDevTool
from crewai_haldir import HaldirSession, GovernedTool   # ← line 1

with HaldirSession.for_agent("research-crew",           # ← line 2
                              scopes=["read", "search"],
                              spend_limit=10.0) as haldir:
    search = GovernedTool.wrap(
        SerperDevTool(),
        client=haldir.client,
        session_id=haldir.session_id,
        required_scope="search",
        cost_usd=0.01,
    )

    researcher = Agent(role="Researcher", goal="...", tools=[search])
    task = Task(description="...", expected_output="...", agent=researcher)
    crew = Crew(agents=[researcher], tasks=[task])

    result = haldir.stamp_sth(crew.kickoff())
    # result["_haldir_sth"] or result._haldir_sth — pin it for
    # offline verification any time later.
```

`HaldirSession.for_agent(...)` reads `HALDIR_API_KEY` + `HALDIR_BASE_URL` from the env. Session auto-revoked on scope exit, including on exception.

## What you get

| Step | Haldir action |
|---|---|
| Session enter | Mints a scoped session with the spend cap |
| GovernedTool `_run` | Checks scope; logs call with input/output/cost |
| `haldir.stamp_sth(result)` | Fetches current STH and attaches to the result |
| Session exit (any path) | Revokes the session |

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
