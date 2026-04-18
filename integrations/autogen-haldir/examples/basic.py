"""
autogen-haldir basic example — a governed research agent.

Run with:
    export OPENAI_API_KEY=sk-...
    export HALDIR_API_KEY=hld_...
    pip install autogen-agentchat autogen-ext autogen-haldir
    python examples/basic.py
"""

import asyncio
import os

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_core.tools import FunctionTool
from autogen_ext.models.openai import OpenAIChatCompletionClient

from autogen_haldir import create_session, govern_tool


async def web_search(query: str) -> str:
    """Return (mocked) search results for the given query."""
    return (
        f"[mock results for '{query}']\n"
        "1. https://example.com/foo — primary source, 2026-01-14\n"
        "2. https://example.com/bar — secondary source, 2026-01-10"
    )


async def main() -> None:
    client, session_id = create_session(
        api_key=os.environ["HALDIR_API_KEY"],
        agent_id="autogen-example-research",
        scopes=["read", "search"],
        spend_limit=1.0,
    )

    raw_search = FunctionTool(
        web_search,
        description="Search the web for up-to-date information.",
    )

    governed_search = govern_tool(
        raw_search,
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
        system_message=(
            "You are a security researcher. Use the search tool to find "
            "primary sources. Cite URLs and dates in your answer."
        ),
    )

    team = RoundRobinGroupChat([agent], max_turns=3)

    print("=== Running governed AutoGen team ===")
    result = await team.run(task="Find a recent MCP security vulnerability report.")
    print("\n=== Answer ===")
    print(result.messages[-1].content if result.messages else "(no messages)")

    trail = client.get_audit_trail(agent_id="autogen-example-research")
    print(f"\n=== Audit trail: {trail['count']} entries ===")
    for entry in trail.get("entries", []):
        cost = entry.get("cost_usd", 0) or 0
        print(f"  [{entry['timestamp']}] {entry['tool']:16}  ${cost:.4f}  ({entry.get('action')})")

    client.revoke_session(session_id)
    print("\nSession revoked.")


if __name__ == "__main__":
    asyncio.run(main())
