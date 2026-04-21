# llamaindex-haldir

Cryptographic-audit + governance for [LlamaIndex](https://llamaindex.ai) tools, agents, and query engines. Two lines of code.

- **Audit trail** — every tool call logged to a SHA-256 hash-chained + RFC 6962 Merkle-covered audit log
- **Scope enforcement** — denied tools abort with `HaldirPermissionError`
- **Secrets vault** — scope-checked credential retrieval as `SecretStr`
- **Tree-head stamping** — current Signed Tree Head attached to the agent's response; pin for offline verification later
- **Instant revocation** — any process can revoke a session mid-run; next tool call aborts
- **Auto-lifecycle** — session minted on `with` entry, revoked on exit even if the agent raises

## Install

```bash
pip install llamaindex-haldir
```

Free Haldir API key at [haldir.xyz](https://haldir.xyz/quickstart).

## Two-line quickstart

```python
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool
from llama_index.llms.openai import OpenAI
from llamaindex_haldir import HaldirSession, govern_tool   # ← line 1

def multiply(a: int, b: int) -> int:
    return a * b

with HaldirSession.for_agent("li-math",                   # ← line 2
                              scopes=["read", "execute"],
                              spend_limit=5.0) as haldir:
    governed = govern_tool(
        FunctionTool.from_defaults(fn=multiply),
        client=haldir.client,
        session_id=haldir.session_id,
        required_scope="execute",
        cost_usd=0.001,
    )

    agent = ReActAgent.from_tools([governed],
                                   llm=OpenAI(model="gpt-4o-mini"))
    resp = haldir.stamp_sth(agent.chat("What is 12 times 13?"))
    # resp._haldir_sth — pin it for offline verification any time later.
```

`HaldirSession.for_agent(...)` reads `HALDIR_API_KEY` + `HALDIR_BASE_URL` from the env. Session auto-revoked on scope exit, including on exception.

## What you get

| Step | Haldir action |
|---|---|
| Session enter | Mints a scoped session with the spend cap |
| `govern_tool` `_run` | Checks scope; logs call with input/output/cost |
| `haldir.stamp_sth(resp)` | Fetches current STH and attaches to response |
| Session exit (any path) | Revokes the session |

# Use as a drop-in LlamaIndex tool
agent = ReActAgent.from_tools([governed], llm=OpenAI(model="gpt-4o-mini"))
response = agent.chat("What is 127 times 39?")
print(response)

# Inspect the audit trail
trail = client.get_audit_trail(agent_id="llamaindex-math-agent")
for entry in trail.get("entries", []):
    print(f"  [{entry['timestamp']}] {entry['tool']}  ${entry.get('cost_usd', 0):.4f}")
```

Every tool call is now:

- **Permission-checked** before execution (revoked or out-of-scope sessions raise `HaldirPermissionError`)
- **Cost-tracked** against the session's `spend_limit`
- **Logged** to Haldir's hash-chained audit trail with tool name, timestamp, and cost

## Works with query engines too

Governance isn't limited to function tools — `QueryEngineTool`, `RetrieverTool`, and any `BaseTool` subclass all work the same way:

```python
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
from llama_index.core.tools import QueryEngineTool, ToolMetadata

# Build a query engine over a folder of docs
index = VectorStoreIndex.from_documents(SimpleDirectoryReader("./docs").load_data())
query_tool = QueryEngineTool(
    query_engine=index.as_query_engine(),
    metadata=ToolMetadata(
        name="docs_search",
        description="Search internal documentation",
    ),
)

# Wrap it
governed_query = govern_tool(
    query_tool,
    client=client,
    session_id=session_id,
    required_scope="search",
    cost_usd=0.005,  # per RAG call
)

agent = ReActAgent.from_tools([governed_query], llm=OpenAI())
```

## Secrets without leaking them to the model

```python
from llamaindex_haldir import HaldirSecrets

# Store once, out-of-band:
# client.store_secret("openai_api_key", "sk_...", scope_required="read")

secrets = HaldirSecrets(client, session_id)
key = secrets.get("openai_api_key")  # pydantic.SecretStr — masked in logs

# Pass into any client that needs the raw value
llm = OpenAI(api_key=key.get_secret_value())
```

If the session doesn't have the required scope, `secrets.get()` raises `HaldirPermissionError`.

## Revoking a run mid-flight

Any process with the Haldir API key can revoke the session — the next tool call halts the agent.

```python
client.revoke_session(session_id)
```

## Variable per-call cost

Handy for RAG where cost scales with retrieved tokens, or any paid API priced by output size:

```python
def rag_cost(response) -> float:
    tokens = getattr(response, "metadata", {}).get("total_tokens", 0)
    return tokens / 1000 * 0.002

governed_query = govern_tool(
    query_tool,
    client=client,
    session_id=session_id,
    required_scope="search",
    cost_fn=rag_cost,
)
```

## Observability-only mode

Want audit trails without blocking? Set your session scopes to include whatever you need (the governance still logs every call), and remove `required_scope` enforcement by passing a wide scope like `"read"` that's always granted. Or subclass `GovernedTool` and override `_check_permission` to always return None — full source is 130 lines.

## API

- `create_session(api_key, agent_id, scopes, ttl, spend_limit, base_url) -> (client, session_id)`
- `govern_tool(tool, client, session_id, required_scope, cost_usd, cost_fn) -> GovernedTool`
- `HaldirSecrets(client, session_id).get(name) -> SecretStr`

## Links

- Haldir: [haldir.xyz](https://haldir.xyz)
- Haldir docs: [haldir.xyz/docs](https://haldir.xyz/docs)
- Source: [github.com/ExposureGuard/haldir](https://github.com/ExposureGuard/haldir/tree/main/integrations/llamaindex-haldir)
- Sibling packages: `langchain-haldir`, `crewai-haldir`, `autogen-haldir`, `@haldir/ai-sdk`

## License

MIT
