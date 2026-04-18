"""
Minimal example: a LangChain ReAct agent governed by Haldir.

Run:
    export HALDIR_API_KEY=hld_xxx
    export OPENAI_API_KEY=sk-xxx
    python basic_agent.py
"""

from __future__ import annotations

import os

from langchain import hub
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import DuckDuckGoSearchRun
from langchain_openai import ChatOpenAI

from langchain_haldir import (
    GovernedTool,
    HaldirCallbackHandler,
    create_session,
)


def main() -> None:
    client, session_id = create_session(
        api_key=os.environ["HALDIR_API_KEY"],
        agent_id="research-agent",
        scopes=["read", "search", "spend"],
        spend_limit=5.0,
        ttl=3600,
    )
    print(f"[+] Haldir session: {session_id}")

    raw_tools = [DuckDuckGoSearchRun()]
    tools = [
        GovernedTool.from_tool(
            t, client, session_id,
            required_scope="search",
            cost_usd=0.01,
        )
        for t in raw_tools
    ]

    callback = HaldirCallbackHandler(
        client, session_id,
        scope_map={"duckduckgo_search": "search"},
        default_scope="read",
        enforce=True,
    )

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    prompt = hub.pull("hwchase17/react")
    agent = create_react_agent(llm, tools, prompt)
    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        callbacks=[callback],
        max_iterations=3,
        handle_parsing_errors=True,
    )

    result = executor.invoke({"input": "What year was the MCP protocol introduced?"})
    print(f"\n[+] Answer: {result['output']}")

    spend = client.get_spend(session_id=session_id)
    print(f"[+] Total spend: ${spend['total_usd']} across {spend['action_count']} actions")

    trail = client.get_audit_trail(session_id=session_id, limit=10)
    print(f"[+] Audit entries: {trail['count']}")
    for e in trail["entries"]:
        print(f"    - {e['tool']}: {e['action']} (${e.get('cost_usd', 0)})")


if __name__ == "__main__":
    main()
