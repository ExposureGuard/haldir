"""
Two-line LangChain agent + Haldir governance.

The entire Haldir wiring is two lines: the `with HaldirSession.for_agent(...)`
context manager and the `callbacks=[haldir.handler]` keyword. Everything else
is standard LangChain.

What this gets you automatically:
  - Scope check on every tool call (denied tools abort the agent)
  - Audit log entry per tool call AND per LLM call
  - USD cost tracked per LLM call via the built-in pricing table
  - Session auto-revoked on scope exit, even on exception
  - Current Signed Tree Head stamped into result["_haldir_sth"]
    so the caller can pin it for offline verification later.

Run:
    export HALDIR_API_KEY=hld_xxx
    export OPENAI_API_KEY=sk-xxx
    python two_line_agent.py
"""

from __future__ import annotations

from langchain import hub
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import DuckDuckGoSearchRun
from langchain_openai import ChatOpenAI

from langchain_haldir import HaldirSession  # ← line 1


def main() -> None:
    # Agent code is just LangChain. Nothing Haldir-specific below
    # except the `callbacks=[haldir.handler]` keyword.
    tools = [DuckDuckGoSearchRun()]
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    prompt = hub.pull("hwchase17/react")
    agent = create_react_agent(llm, tools, prompt)

    with HaldirSession.for_agent(  # ← line 2
        "research-agent",
        scopes=["read", "search"],
        spend_limit=5.0,
    ) as haldir:
        executor = AgentExecutor(
            agent=agent,
            tools=tools,
            callbacks=[haldir.handler],
            max_iterations=3,
            handle_parsing_errors=True,
        )
        result = executor.invoke(
            {"input": "What year was the MCP protocol introduced?"},
        )

        print(f"[+] Answer: {result['output']}")
        print(f"[+] Haldir session: {haldir.session_id}")
        print(f"[+] Spend so far: ${haldir.spend_summary()['total_usd']}")

        sth = result.get("_haldir_sth")
        if sth:
            print(
                f"[+] Pinned STH: tree_size={sth['tree_size']} "
                f"root={sth['root_hash'][:16]}… algo={sth['algorithm']}"
            )
            print(
                "    Save this STH. Run haldir.verify_inclusion_proof() "
                "against it any time later to prove the run's audit log "
                "hasn't been rewritten."
            )


if __name__ == "__main__":
    main()
