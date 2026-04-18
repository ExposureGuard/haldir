# autogen-haldir

Governance layer for AutoGen agents — audit trails, spend caps, secrets vault, and instant revocation.

Wrap any AutoGen tool in Haldir's enforcement proxy so every tool call is scope-checked, cost-tracked, and logged to a tamper-evident hash-chained audit trail. Works with AutoGen 0.4+ (`autogen-agentchat` / `autogen-core`).

## Install

```bash
pip install autogen-haldir
```

You'll need a Haldir API key. Create one free at [haldir.xyz](https://haldir.xyz/quickstart).

## 30-second quickstart

```python
import asyncio
import os

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_core.tools import FunctionTool
from autogen_ext.models.openai import OpenAIChatCompletionClient

from autogen_haldir import create_session, govern_tool


async def main():
    # Create a scoped Haldir session with a $10 spend cap
    client, session_id = create_session(
        api_key=os.environ["HALDIR_API_KEY"],
        agent_id="autogen-research-agent",
        scopes=["read", "search", "spend"],
        spend_limit=10.0,
    )

    # Define a normal AutoGen tool
    async def web_search(query: str) -> str:
        """Search the web for the given query."""
        return f"results for: {query}"

    raw_tool = FunctionTool(
        web_search,
        description="Search the web for up-to-date information.",
    )

    # Wrap it — permissions and audit are now enforced on every call
    governed_search = govern_tool(
        raw_tool,
        client=client,
        session_id=session_id,
        required_scope="search",
        cost_usd=0.003,
    )

    # Build the agent as usual
    model = OpenAIChatCompletionClient(model="gpt-4o-mini")
    agent = AssistantAgent(
        name="researcher",
        model_client=model,
        tools=[governed_search],
        system_message="You are a meticulous research agent.",
    )

    team = RoundRobinGroupChat([agent], max_turns=3)
    result = await team.run(task="What's the latest news on MCP security?")
    print(result)

    # See what happened
    trail = client.get_audit_trail(agent_id="autogen-research-agent")
    for e in trail.get("entries", []):
        print(f"[{e['timestamp']}] {e['tool']} -> {e['action']}  ${e.get('cost_usd', 0):.4f}")


asyncio.run(main())
```

Every tool call is now:

- **Permission-checked** before execution (revoked or out-of-scope sessions raise `HaldirPermissionError`)
- **Cost-tracked** against the session's `spend_limit`
- **Logged** to Haldir's hash-chained audit trail with tool name, timestamp, and cost

## Secrets without leaking them to the model

```python
from autogen_haldir import HaldirSecrets

# Store the secret once, out-of-band (not from the agent):
# client.store_secret("api_key", "sk_live_xxx", scope_required="spend")

secrets = HaldirSecrets(client, session_id)
key = secrets.get("api_key")  # pydantic.SecretStr — masked in logs

# Use inside your tool when you actually need the raw value
import stripe
stripe.api_key = key.get_secret_value()
```

If the session's scopes don't include the required scope, `secrets.get()` raises `HaldirPermissionError`.

## Revoking a run mid-flight

Any process with the Haldir API key can revoke the session — the next tool call halts the AutoGen run.

```python
client.revoke_session(session_id)
```

This is the kill switch for misbehaving multi-agent teams.

## Variable per-call cost

For tools where cost depends on the result (LLM inference, paid APIs, metered services), pass `cost_fn`:

```python
def scraper_cost(result: str) -> float:
    return len(result) / 1000 * 0.005  # $0.005 per 1k chars

governed_scraper = govern_tool(
    scraper_tool,
    client=client,
    session_id=session_id,
    required_scope="read",
    cost_fn=scraper_cost,
)
```

## Multi-agent teams

Use one session per team, or one per agent — whichever you want to scope to. With one-per-team, the aggregate spend cap applies to the whole conversation. With one-per-agent, each agent has its own budget and scope list.

```python
researcher_client, researcher_sid = create_session(
    api_key=key, agent_id="researcher", scopes=["search"], spend_limit=5.0,
)
writer_client, writer_sid = create_session(
    api_key=key, agent_id="writer", scopes=["read"], spend_limit=2.0,
)

# Wrap tools accordingly for each agent
```

## API

- `create_session(api_key, agent_id, scopes, ttl, spend_limit, base_url) -> (client, session_id)`
- `govern_tool(tool, client, session_id, required_scope, cost_usd, cost_fn) -> GovernedFunctionTool`
- `HaldirSecrets(client, session_id).get(name) -> SecretStr`

## Links

- Haldir: [haldir.xyz](https://haldir.xyz)
- Haldir docs: [haldir.xyz/docs](https://haldir.xyz/docs)
- Source: [github.com/ExposureGuard/haldir](https://github.com/ExposureGuard/haldir/tree/main/integrations/autogen-haldir)
- Sibling packages: `langchain-haldir`, `crewai-haldir`, `@haldir/ai-sdk`

## License

MIT
