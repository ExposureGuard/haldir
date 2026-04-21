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

"""Exports. `GovernedTool` requires the `crewai` package to be
installed; if the user hasn't installed it yet, `HaldirSession` +
`HaldirSecrets` still work standalone. Lazy import keeps the package
importable even before `pip install crewai` so the session-level
surface is testable in CI without the heavy dep chain."""

from .session import HaldirSession, create_session
from .secrets import HaldirSecrets

__all__ = [
    "HaldirSession",
    "create_session",
    "GovernedTool",
    "HaldirSecrets",
]

__version__ = "0.2.0"


def __getattr__(name: str):
    if name == "GovernedTool":
        from .governed_tool import GovernedTool
        return GovernedTool
    raise AttributeError(f"module 'crewai_haldir' has no attribute {name!r}")
