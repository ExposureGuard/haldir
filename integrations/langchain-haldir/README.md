# langchain-haldir

Governance layer for LangChain agents — audit trails, spend caps, secrets vault, and instant revocation.

Wrap any LangChain agent or tool in Haldir's enforcement proxy so every tool call is scope-checked, cost-tracked, and logged to a tamper-evident audit trail.

## Install

```bash
pip install langchain-haldir
```

You'll also need a Haldir API key. Create one free at [haldir.xyz](https://haldir.xyz).

## 30-second quickstart

```python
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import DuckDuckGoSearchRun
from langchain_openai import ChatOpenAI
from langchain_haldir import HaldirCallbackHandler, GovernedTool, create_session

# Create a scoped Haldir session with a $10 spend cap
client, session_id = create_session(
    api_key="hld_xxx",
    agent_id="my-research-agent",
    scopes=["read", "search", "spend"],
    spend_limit=10.0,
)

# Wrap your tools so Haldir enforces permissions
raw_tools = [DuckDuckGoSearchRun()]
tools = [
    GovernedTool.from_tool(t, client, session_id, required_scope="search", cost_usd=0.01)
    for t in raw_tools
]

# Attach the callback for hash-chained audit logging
callback = HaldirCallbackHandler(client, session_id, enforce=True)

llm = ChatOpenAI(model="gpt-4o-mini")
agent = create_react_agent(llm, tools, prompt="...")
executor = AgentExecutor(agent=agent, tools=tools, callbacks=[callback])

executor.invoke({"input": "Who won the 2024 Nobel Peace Prize?"})
```

Every tool call is now:
- **Permission-checked** before execution (revoked or out-of-scope sessions raise `HaldirPermissionError`)
- **Cost-tracked** against the session's `spend_limit`
- **Logged** to Haldir's hash-chained audit trail with input, output, and timestamp

## Secrets without leaking them to the model

```python
from langchain_haldir import HaldirSecrets

# Store the secret once (out-of-band, not from the agent):
# client.store_secret("stripe_api_key", "sk_live_xxx", scope_required="spend")

secrets = HaldirSecrets(client, session_id)
stripe_key = secrets.get("stripe_api_key")  # Returns SecretStr — masked in logs

# Use in your tool — the raw value never enters an LLM prompt
import stripe
stripe.api_key = stripe_key.get_secret_value()
```

If the session's scopes don't include `spend`, `secrets.get()` raises `HaldirPermissionError`.

## Revoking an agent mid-run

Any process with the Haldir API key can revoke the session — agent execution halts on the next tool call.

```python
client.revoke_session(session_id)  # next tool call → HaldirPermissionError
```

Combined with approval webhooks (see [haldir.xyz/docs](https://haldir.xyz/docs)), this gives humans a kill switch over any running agent.

## Observability-only mode

If you only want logging without enforcement:

```python
HaldirCallbackHandler(client, session_id, enforce=False)
```

Every tool call is still logged to the audit trail, but permission failures don't block execution.

## Scope mapping

Pass a `scope_map` to the callback to route different tools through different scopes:

```python
HaldirCallbackHandler(
    client, session_id,
    scope_map={
        "duckduckgo_search": "search",
        "python_repl": "execute",
        "requests_post": "write",
    },
    default_scope="read",
)
```

## API

- `create_session(api_key, agent_id, scopes, ttl, spend_limit, base_url) -> (client, session_id)`
- `HaldirCallbackHandler(client, session_id, scope_map, default_scope, enforce, cost_fn)`
- `GovernedTool.from_tool(tool, client, session_id, required_scope, cost_usd) -> GovernedTool`
- `HaldirSecrets(client, session_id).get(name) -> SecretStr`

## Links

- Haldir: [haldir.xyz](https://haldir.xyz)
- Haldir docs: [haldir.xyz/docs](https://haldir.xyz/docs)
- PyPI: [pypi.org/project/langchain-haldir](https://pypi.org/project/langchain-haldir/)
- Source: [github.com/ExposureGuard/haldir](https://github.com/ExposureGuard/haldir/tree/main/integrations/langchain-haldir)

## License

MIT
