"""
Haldir + LangChain — a governed research agent.

Shows every piece the LangChain integration gives you:

  - create_session:       scoped session with a $10 cap
  - GovernedTool.from_tool: every tool is permission-checked before execution
  - HaldirCallbackHandler:  every tool call is logged to the audit trail
  - HaldirSecrets:          retrieve an API key without ever putting it in
                            the model prompt (SecretStr masks in logs)

Run:
    pip install langchain-haldir langchain-openai duckduckgo-search
    export OPENAI_API_KEY=sk-...
    export HALDIR_API_KEY=hld_...
    python examples/langchain_agent.py
"""

from __future__ import annotations

import os

from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import DuckDuckGoSearchRun
from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI

from langchain_haldir import (
    GovernedTool,
    HaldirCallbackHandler,
    HaldirSecrets,
    create_session,
)


# ── 1. Create a scoped Haldir session ────────────────────────────────────

client, session_id = create_session(
    api_key=os.environ["HALDIR_API_KEY"],
    agent_id="langchain-research-agent",
    scopes=["read", "search", "spend"],
    spend_limit=10.0,          # cumulative USD cap across this whole run
    ttl=3600,                   # auto-expire after 1 hour
)

# ── 2. Retrieve secrets without leaking them to the LLM ──────────────────

# Store the secret once, out-of-band. Normally you'd do this via a deploy-time
# admin script, not from inside the agent. Uncomment once per environment:
#
#     client.store_secret("some_api_key", "sk_live_xxx", scope_required="read")

secrets = HaldirSecrets(client, session_id)
# If/when the agent needs the key, unwrap it locally — the raw value never
# enters the LangChain prompt or trace:
#     raw = secrets.get("some_api_key").get_secret_value()

# ── 3. Wrap tools so every call is scope-checked + audit-logged ──────────

search = GovernedTool.from_tool(
    DuckDuckGoSearchRun(),
    client=client,
    session_id=session_id,
    required_scope="search",   # this session must carry "search" to use the tool
    cost_usd=0.01,              # flat per-call cost (use cost_fn for variable)
)

# ── 4. Callback: permission check + audit write on every tool call ──────

callback = HaldirCallbackHandler(
    client=client,
    session_id=session_id,
    enforce=True,               # False = log-only (observability mode)
)

# ── 5. Build the agent as normal — governance is transparent ────────────

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

prompt = PromptTemplate.from_template("""Answer the user's question. You have access to:

{tools}

Use this format:
Thought: think about what to do
Action: the action, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result

... (repeat Thought/Action/Observation as needed)
Final Answer: the answer to the original question

Question: {input}
{agent_scratchpad}""")

agent = create_react_agent(llm, [search], prompt)
executor = AgentExecutor(
    agent=agent,
    tools=[search],
    callbacks=[callback],
    verbose=True,
    max_iterations=4,
)

# ── 6. Run ────────────────────────────────────────────────────────────────

result = executor.invoke({"input": "Who won the 2024 Nobel Peace Prize?"})
print("\n=== Answer ===\n", result["output"])

# ── 7. Inspect the audit trail ────────────────────────────────────────────

trail = client.get_audit_trail(agent_id="langchain-research-agent", limit=20)
print(f"\n=== Audit trail: {trail['count']} entries ===")
for entry in trail.get("entries", []):
    cost = entry.get("cost_usd", 0) or 0
    print(f"  [{entry['timestamp']}] {entry['tool']:20} ${cost:.4f}  ({entry.get('action', '-')})")

spend = client.get_spend(agent_id="langchain-research-agent")
print(f"\n=== Total spend: ${spend['total_usd']:.4f} across {spend['action_count']} actions ===")

# ── 8. Kill the session when done ─────────────────────────────────────────

client.revoke_session(session_id)
print("\nSession revoked. Any subsequent tool call would raise HaldirPermissionError.")
