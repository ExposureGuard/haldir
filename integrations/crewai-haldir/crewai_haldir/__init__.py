"""
crewai-haldir — Governance layer for CrewAI agents.

Wrap any CrewAI tool in Haldir's enforcement proxy so every tool call is
scope-checked, cost-tracked, and logged to a tamper-evident audit trail.

Quick start:

    from crewai import Agent, Task, Crew
    from crewai_tools import SerperDevTool
    from crewai_haldir import create_session, GovernedTool, HaldirSecrets

    client, session_id = create_session(
        api_key="hld_xxx",
        agent_id="research-crew",
        scopes=["read", "search"],
        spend_limit=10.0,
    )

    search = GovernedTool.wrap(
        SerperDevTool(),
        client=client,
        session_id=session_id,
        required_scope="search",
        cost_usd=0.01,
    )

    researcher = Agent(role="Researcher", goal="...", tools=[search])
    crew = Crew(agents=[researcher], tasks=[Task(...)])
    crew.kickoff()
"""

from .session import create_session
from .governed_tool import GovernedTool
from .secrets import HaldirSecrets

__all__ = [
    "create_session",
    "GovernedTool",
    "HaldirSecrets",
]

__version__ = "0.1.0"
