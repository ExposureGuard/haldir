"""
llamaindex-haldir basic example — a governed ReAct agent.

Run with:
    export OPENAI_API_KEY=sk-...
    export HALDIR_API_KEY=hld_...
    pip install llama-index-core llama-index-llms-openai llamaindex-haldir
    python examples/basic.py
"""

import os

from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool
from llama_index.llms.openai import OpenAI

from llamaindex_haldir import create_session, govern_tool


def multiply(a: int, b: int) -> int:
    """Multiply two integers."""
    return a * b


def divide(a: float, b: float) -> float:
    """Divide two numbers."""
    return a / b


def main() -> None:
    client, session_id = create_session(
        api_key=os.environ["HALDIR_API_KEY"],
        agent_id="llamaindex-example-math",
        scopes=["read", "execute"],
        spend_limit=1.0,
    )

    # Wrap both tools
    governed_multiply = govern_tool(
        FunctionTool.from_defaults(fn=multiply),
        client=client,
        session_id=session_id,
        required_scope="execute",
        cost_usd=0.001,
    )
    governed_divide = govern_tool(
        FunctionTool.from_defaults(fn=divide),
        client=client,
        session_id=session_id,
        required_scope="execute",
        cost_usd=0.001,
    )

    agent = ReActAgent.from_tools(
        [governed_multiply, governed_divide],
        llm=OpenAI(model="gpt-4o-mini"),
        verbose=True,
    )

    print("=== Running governed LlamaIndex agent ===")
    response = agent.chat("What is 127 times 39, then divided by 3?")
    print(f"\n=== Answer ===\n{response}")

    trail = client.get_audit_trail(agent_id="llamaindex-example-math")
    print(f"\n=== Audit trail: {trail['count']} entries ===")
    for entry in trail.get("entries", []):
        cost = entry.get("cost_usd", 0) or 0
        print(f"  [{entry['timestamp']}] {entry['tool']:12}  ${cost:.4f}  ({entry.get('action')})")

    client.revoke_session(session_id)
    print("\nSession revoked.")


if __name__ == "__main__":
    main()
