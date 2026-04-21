"""
llamaindex-haldir — governance layer for LlamaIndex tools and query engines.

Wrap any LlamaIndex `BaseTool` (including `FunctionTool` and `QueryEngineTool`)
with Haldir enforcement: scope checks on every call, cost tracking against a
per-session budget, hash-chained audit trail, and instant session revocation.

Quick start:

    import os
    from llama_index.core.tools import FunctionTool
    from llama_index.core.agent import ReActAgent
    from llama_index.llms.openai import OpenAI
    from llamaindex_haldir import create_session, govern_tool, HaldirSecrets

    client, sid = create_session(
        api_key=os.environ["HALDIR_API_KEY"],
        agent_id="llamaindex-research",
        scopes=["read", "search", "spend"],
        spend_limit=10.0,
    )

    def multiply(a: int, b: int) -> int:
        return a * b

    raw = FunctionTool.from_defaults(fn=multiply)
    governed = govern_tool(raw, client=client, session_id=sid,
                           required_scope="execute", cost_usd=0.001)

    agent = ReActAgent.from_tools([governed], llm=OpenAI(model="gpt-4o-mini"))
    agent.chat("What is 12 times 13?")
"""

"""Exports. `GovernedTool` / `govern_tool` need the `llama_index`
package installed; if the user hasn't installed it yet, `HaldirSession`
+ `HaldirSecrets` still work standalone. Lazy import keeps the package
importable even before `pip install llama-index`."""

from .secrets import HaldirSecrets
from .session import HaldirSession, create_session

__all__ = [
    "HaldirSession",
    "create_session",
    "govern_tool",
    "GovernedTool",
    "HaldirSecrets",
]

__version__ = "0.2.0"


def __getattr__(name: str):
    if name in ("GovernedTool", "govern_tool"):
        from .governed_tool import GovernedTool, govern_tool
        return {"GovernedTool": GovernedTool, "govern_tool": govern_tool}[name]
    raise AttributeError(f"module 'llamaindex_haldir' has no attribute {name!r}")
