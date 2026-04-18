"""
autogen-haldir — governance layer for AutoGen agents.

Wrap any AutoGen tool with Haldir enforcement: scope checks on every call,
cost tracking against a per-session budget, hash-chained audit trail, and
instant session revocation.

Quick start:

    import os
    from autogen_agentchat.agents import AssistantAgent
    from autogen_core.tools import FunctionTool
    from autogen_ext.models.openai import OpenAIChatCompletionClient
    from autogen_haldir import create_session, govern_tool, HaldirSecrets

    client, session_id = create_session(
        api_key=os.environ["HALDIR_API_KEY"],
        agent_id="research-bot",
        scopes=["read", "search", "spend"],
        spend_limit=10.0,
    )

    async def search(query: str) -> str:
        return f"results for: {query}"

    search_tool = FunctionTool(search, description="Web search")
    governed_search = govern_tool(
        search_tool,
        client=client,
        session_id=session_id,
        required_scope="search",
        cost_usd=0.003,
    )

    model = OpenAIChatCompletionClient(model="gpt-4o-mini")
    agent = AssistantAgent(
        name="researcher",
        model_client=model,
        tools=[governed_search],
    )
"""

from .governed_tool import govern_tool, GovernedFunctionTool
from .secrets import HaldirSecrets
from .session import create_session

__all__ = [
    "create_session",
    "govern_tool",
    "GovernedFunctionTool",
    "HaldirSecrets",
]

__version__ = "0.1.0"
