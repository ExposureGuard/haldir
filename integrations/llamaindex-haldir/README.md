# llamaindex-haldir

Governance layer for [LlamaIndex](https://llamaindex.ai) tools and query engines — audit trails, spend caps, secrets vault, and instant revocation.

Wrap any LlamaIndex `BaseTool` (including `FunctionTool` and `QueryEngineTool`) in Haldir's enforcement proxy so every call is scope-checked, cost-tracked, and logged to a hash-chained tamper-evident audit trail.

## Install

```bash
pip install llamaindex-haldir
```

You'll need a Haldir API key. Create one free at [haldir.xyz](https://haldir.xyz/quickstart).

## 30-second quickstart

```python
import os
from llama_index.core.tools import FunctionTool
from llama_index.core.agent import ReActAgent
from llama_index.llms.openai import OpenAI

from llamaindex_haldir import create_session, govern_tool


# Create a scoped Haldir session with a $5 spend cap
client, session_id = create_session(
    api_key=os.environ["HALDIR_API_KEY"],
    agent_id="llamaindex-math-agent",
    scopes=["read", "execute", "spend"],
    spend_limit=5.0,
)

# Define a normal LlamaIndex tool
def multiply(a: int, b: int) -> int:
    """Multiply two integers."""
    return a * b

raw = FunctionTool.from_defaults(fn=multiply)

# Wrap it — permissions + audit are now enforced on every call
governed = govern_tool(
    raw,
    client=client,
    session_id=session_id,
    required_scope="execute",
    cost_usd=0.001,
)

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
