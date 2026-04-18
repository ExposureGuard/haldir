"""
Basic crewai-haldir example: a single researcher crew with governed search.

Run with:
    export OPENAI_API_KEY=sk-...
    export HALDIR_API_KEY=hld_...
    export SERPER_API_KEY=...
    python examples/basic.py
"""

import os

from crewai import Agent, Crew, Task
from crewai_tools import SerperDevTool

from crewai_haldir import GovernedTool, create_session


def main() -> None:
    client, session_id = create_session(
        api_key=os.environ["HALDIR_API_KEY"],
        agent_id="example-research-crew",
        scopes=["read", "search"],
        spend_limit=5.0,
    )

    search = GovernedTool.wrap(
        SerperDevTool(),
        client=client,
        session_id=session_id,
        required_scope="search",
        cost_usd=0.005,
    )

    researcher = Agent(
        role="Security News Researcher",
        goal="Surface recent AI agent security news with sources",
        backstory="A skeptical analyst who only trusts primary sources.",
        tools=[search],
        verbose=True,
    )

    task = Task(
        description="Find three recent articles about AI agent security or governance.",
        expected_output="A bulleted list with URL, publication date, and one-line summary for each.",
        agent=researcher,
    )

    crew = Crew(agents=[researcher], tasks=[task], verbose=True)
    result = crew.kickoff()

    print("\n=== Result ===")
    print(result)

    print("\n=== Audit trail ===")
    trail = client.get_audit_trail(agent_id="example-research-crew")
    for entry in trail.get("entries", []):
        print(f"  [{entry['timestamp']}] {entry['tool']} — ${entry.get('cost_usd', 0):.4f}")


if __name__ == "__main__":
    main()
