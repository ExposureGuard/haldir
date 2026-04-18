"""
Haldir + CrewAI — a governed research crew.

Wraps CrewAI tools with GovernedTool.wrap() so every tool call made by any
agent in the crew is scope-checked, cost-tracked, and audit-logged.

Run:
    pip install crewai crewai-tools crewai-haldir
    export OPENAI_API_KEY=sk-...
    export HALDIR_API_KEY=hld_...
    export SERPER_API_KEY=...              # serper.dev web search
    python examples/crewai_crew.py
"""

from __future__ import annotations

import os

from crewai import Agent, Crew, Task
from crewai_tools import SerperDevTool

from crewai_haldir import GovernedTool, create_session


# ── 1. Create a scoped Haldir session ────────────────────────────────────

client, session_id = create_session(
    api_key=os.environ["HALDIR_API_KEY"],
    agent_id="crewai-research-crew",
    scopes=["read", "search", "spend"],
    spend_limit=5.0,
    ttl=3600,
)

# ── 2. Wrap CrewAI tools with Haldir enforcement ─────────────────────────

# SerperDevTool charges per search — give it a variable cost based on
# actual result size so the audit trail reflects real economics.
def serper_cost(result: object) -> float:
    # serper.dev costs ~$0.003/search regardless of size; flat rate is fine
    return 0.003


search = GovernedTool.wrap(
    SerperDevTool(),
    client=client,
    session_id=session_id,
    required_scope="search",
    cost_fn=serper_cost,
)

# ── 3. Build the crew — governance is transparent ────────────────────────

researcher = Agent(
    role="Senior Security Research Analyst",
    goal="Surface recent AI agent security incidents with primary sources",
    backstory=(
        "A skeptical security analyst who only trusts primary sources. "
        "You cite URLs, publication dates, and one-line summaries."
    ),
    tools=[search],
    verbose=True,
    allow_delegation=False,
)

task = Task(
    description=(
        "Find three recent (last 60 days) news items about AI agent security "
        "incidents, prompt injection attacks, or governance failures. "
        "For each, return: URL, publication date, one-line summary."
    ),
    expected_output="Numbered list: URL, date, summary. Three items total.",
    agent=researcher,
)

crew = Crew(
    agents=[researcher],
    tasks=[task],
    verbose=True,
)

# ── 4. Run ────────────────────────────────────────────────────────────────

result = crew.kickoff()
print("\n=== Result ===")
print(result)

# ── 5. Inspect the audit trail ────────────────────────────────────────────

trail = client.get_audit_trail(agent_id="crewai-research-crew", limit=20)
print(f"\n=== Audit trail: {trail['count']} entries ===")
for entry in trail.get("entries", []):
    cost = entry.get("cost_usd", 0) or 0
    print(f"  [{entry['timestamp']}] {entry['tool']:20} ${cost:.4f}  ({entry.get('action', '-')})")

spend = client.get_spend(agent_id="crewai-research-crew")
print(f"\n=== Total spend: ${spend['total_usd']:.4f} across {spend['action_count']} actions ===")
print(f"    Remaining budget: ${5.0 - spend['total_usd']:.4f}")

# ── 6. Kill the session ───────────────────────────────────────────────────

client.revoke_session(session_id)
print("\nSession revoked. Crew cannot make further tool calls.")
