# langchain-haldir

Cryptographic-audit + governance layer for LangChain agents. Two lines of code.

- **Audit trail** — every tool call AND every LLM call logged to a SHA-256 hash-chained + RFC 6962 Merkle-covered audit log
- **Spend caps** — LLM token cost tracked automatically via a built-in pricing table (OpenAI, Anthropic, Google, DeepSeek, Llama, Mistral)
- **Tree-head stamping** — every agent run returns the Signed Tree Head that covers its audit entries; pin it for offline verification later
- **Scope enforcement** — denied tools abort the agent loop with a clean `HaldirPermissionError`
- **Secrets vault** — retrieve scope-checked credentials as LangChain `SecretStr`
- **Instant revocation** — any process can revoke a session mid-run; next tool call aborts

## Install

```bash
pip install langchain-haldir
```

Free Haldir API key at [haldir.xyz](https://haldir.xyz).

## Two-line quickstart

```python
from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI
from langchain_haldir import HaldirSession           # ← line 1

agent    = create_react_agent(ChatOpenAI(model="gpt-4o-mini"), tools, prompt)

with HaldirSession.for_agent("research-bot",         # ← line 2
                             scopes=["read", "search"],
                             spend_limit=5.0) as haldir:
    executor = AgentExecutor(agent=agent, tools=tools,
                             callbacks=[haldir.handler])
    result = executor.invoke({"input": "..."})

# Everything on exit:
#   - Session revoked.
#   - Every tool + LLM call is in the audit log.
#   - result["_haldir_sth"] carries the STH you can pin for
#     offline verification later.
```

`HaldirSession.for_agent(...)` reads `HALDIR_API_KEY` + `HALDIR_BASE_URL` from the env. Set them once; every agent you run is governed.

## What you get for free

Every LangChain call is now:

| Event | What Haldir writes to the audit log |
|---|---|
| `on_tool_start` | Scope check (aborts on deny); caches input |
| `on_tool_end` | `tool_call` with input/output + optional `cost_fn` |
| `on_tool_error` | `tool_error` with the exception |
| `on_llm_end` | `llm_call` with `model`, `prompt_tokens`, `completion_tokens`, and **USD cost from the built-in pricing table** |
| `on_agent_finish` | Fetches current STH and stamps `_haldir_sth` onto `return_values` |

Pricing table covers GPT-4o, GPT-4, o1, Claude 3.5/3.7/4, Gemini 1.5/2.0/2.5, Llama 3.1/3.3, DeepSeek, Mistral. Unknown models fall back to a conservative rate that fires the budget early rather than late.

## Secrets without leaking them to the model

```python
from langchain_haldir import HaldirSecrets

with HaldirSession.for_agent("stripe-bot",
                             scopes=["spend"]) as haldir:
    secrets = HaldirSecrets(haldir.client, haldir.session_id)
    stripe_key = secrets.get("stripe_api_key")   # SecretStr — masks in logs
    # ... pass to your tool; raw value never enters an LLM prompt
```

If the session's scopes don't satisfy the secret's `scope_required`, `secrets.get()` raises `HaldirPermissionError`.

## Revoking mid-run

Any process with the Haldir API key can revoke the session. The next tool call aborts.

```python
client.revoke_session(session_id)  # next tool call → HaldirPermissionError
```

Combined with approval webhooks (see [haldir.xyz/docs](https://haldir.xyz/docs)), this is a human kill-switch on any running agent.

## Observability-only mode

```python
with HaldirSession.for_agent("observe",
                             enforce=False) as haldir:
    ...  # every call logged; permission failures don't block
```

## Explicit path (no context manager)

If your agent lifecycle is managed elsewhere and you just want the handler:

```python
from langchain_haldir import HaldirCallbackHandler

handler = HaldirCallbackHandler.from_env(session_id="ses_xxx")
AgentExecutor(..., callbacks=[handler])
```

## Per-tool scope routing

```python
handler = HaldirCallbackHandler.from_env(
    session_id=session_id,
    scope_map={
        "duckduckgo_search":  "search",
        "python_repl":        "execute",
        "requests_post":      "write",
    },
    default_scope="read",
)
```

## Hard-enforcement wrapper (GovernedTool)

Use when you need the scope check to run at tool invocation rather than at LangChain's callback boundary:

```python
from langchain_haldir import GovernedTool

tools = [
    GovernedTool.from_tool(
        raw_tool,
        haldir.client,
        haldir.session_id,
        required_scope="search",
        cost_usd=0.01,
    )
    for raw_tool in raw_tools
]
```

`GovernedTool._run` runs the scope check synchronously inside the tool itself, so any code path that invokes the tool — callbacks enabled or not — hits the gate.

## API surface

- `HaldirSession(api_key, base_url, agent_id, scopes, ttl, spend_limit, scope_map, default_scope, enforce, track_llm_cost, stamp_sth)` — context manager; auto-mint + auto-revoke
- `HaldirSession.for_agent(agent_id, scopes=..., spend_limit=...)` — same, reads `HALDIR_API_KEY` / `HALDIR_BASE_URL` from env
- `HaldirCallbackHandler(client, session_id, ...)` — LangChain BaseCallbackHandler; enforce + audit + LLM cost + STH stamp
- `HaldirCallbackHandler.from_env(session_id, ...)` — build the handler without constructing a client first
- `GovernedTool.from_tool(tool, client, session_id, required_scope, cost_usd)` — hard-enforcement wrapper
- `HaldirSecrets(client, session_id).get(name) -> SecretStr` — scope-checked vault retrieval
- `create_session(...)` — legacy helper (returns `(client, session_id)`); prefer `HaldirSession`

## Links

- Haldir: [haldir.xyz](https://haldir.xyz)
- Haldir docs: [haldir.xyz/docs](https://haldir.xyz/docs)
- PyPI: [pypi.org/project/langchain-haldir](https://pypi.org/project/langchain-haldir/)
- Source: [github.com/ExposureGuard/haldir](https://github.com/ExposureGuard/haldir/tree/main/integrations/langchain-haldir)

## License

MIT
