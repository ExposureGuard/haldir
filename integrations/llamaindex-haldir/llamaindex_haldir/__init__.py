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

from .governed_tool import GovernedTool, govern_tool
from .secrets import HaldirSecrets
from .session import create_session

__all__ = [
    "create_session",
    "govern_tool",
    "GovernedTool",
    "HaldirSecrets",
]

__version__ = "0.1.0"
