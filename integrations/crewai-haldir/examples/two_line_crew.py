"""
Two-line CrewAI + Haldir governance.

The entire Haldir wiring is two lines — `with HaldirSession.for_agent(...)`
plus `GovernedTool.wrap(...)` per tool you want to harden. Everything
else is standard CrewAI.

What this gets you automatically:
  - Scope check on every tool call (denied tools abort)
  - Audit log entry per tool call with input + output
  - Session auto-revoked on scope exit, even on exception
  - Current Signed Tree Head attached to the crew's output so the
    caller can pin it for offline verification later.

Run:
    export HALDIR_API_KEY=hld_xxx
    export OPENAI_API_KEY=sk-xxx
    export SERPER_API_KEY=...
    python two_line_crew.py
"""

from __future__ import annotations

from crewai import Agent, Crew, Task
from crewai_tools import SerperDevTool

from crewai_haldir import GovernedTool, HaldirSession  # ← line 1


def main() -> None:
    with HaldirSession.for_agent(                     # ← line 2
        "research-crew",
        scopes=["read", "search"],
        spend_limit=10.0,
    ) as haldir:
        search = GovernedTool.wrap(
            SerperDevTool(),
            client=haldir.client,
            session_id=haldir.session_id,
            required_scope="search",
            cost_usd=0.01,
        )
        researcher = Agent(
            role="Researcher",
            goal="Find accurate, current information",
            backstory="You verify sources carefully.",
            tools=[search],
            allow_delegation=False,
        )
        task = Task(
            description="What year was the MCP protocol introduced?",
            expected_output="A single-sentence answer citing the year.",
            agent=researcher,
        )
        crew = Crew(agents=[researcher], tasks=[task])

        # Stamp the STH onto the result so an auditor can pin it later.
        result = haldir.stamp_sth(crew.kickoff())

        print(f"[+] Answer: {result}")
        print(f"[+] Session spend: ${haldir.spend_summary()['total_usd']}")

        sth = (
            result.get("_haldir_sth")
            if isinstance(result, dict) else getattr(result, "_haldir_sth", None)
        )
        if sth:
            print(
                f"[+] Pinned STH: tree_size={sth['tree_size']} "
                f"root={sth['root_hash'][:16]}… algo={sth['algorithm']}"
            )


if __name__ == "__main__":
    main()
