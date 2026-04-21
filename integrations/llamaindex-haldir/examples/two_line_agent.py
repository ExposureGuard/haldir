"""
Two-line LlamaIndex + Haldir governance.

The entire Haldir wiring is two lines — `with HaldirSession.for_agent(...)`
plus `govern_tool(...)` per tool you want to harden. Everything else is
standard LlamaIndex.

What this gets you automatically:
  - Scope check on every tool call (denied tools abort)
  - Audit log entry per tool call with input + output + cost
  - Session auto-revoked on scope exit, even on exception
  - Current Signed Tree Head attached to the agent's response so the
    caller can pin it for offline verification later.

Run:
    export HALDIR_API_KEY=hld_xxx
    export OPENAI_API_KEY=sk-xxx
    python two_line_agent.py
"""

from __future__ import annotations

from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool
from llama_index.llms.openai import OpenAI

from llamaindex_haldir import HaldirSession, govern_tool   # ← line 1


def multiply(a: int, b: int) -> int:
    """Compute a * b."""
    return a * b


def main() -> None:
    with HaldirSession.for_agent(                         # ← line 2
        "li-research",
        scopes=["read", "execute"],
        spend_limit=5.0,
    ) as haldir:
        raw = FunctionTool.from_defaults(fn=multiply)
        governed = govern_tool(
            raw,
            client=haldir.client,
            session_id=haldir.session_id,
            required_scope="execute",
            cost_usd=0.001,
        )

        agent = ReActAgent.from_tools(
            [governed],
            llm=OpenAI(model="gpt-4o-mini", temperature=0),
        )

        # Stamp the STH onto the response so an auditor can pin it.
        resp = haldir.stamp_sth(agent.chat("What is 12 times 13?"))

        print(f"[+] Answer: {resp}")
        print(f"[+] Session spend: ${haldir.spend_summary()['total_usd']}")

        sth = getattr(resp, "_haldir_sth", None) or (
            resp.get("_haldir_sth") if isinstance(resp, dict) else None
        )
        if sth:
            print(
                f"[+] Pinned STH: tree_size={sth['tree_size']} "
                f"root={sth['root_hash'][:16]}… algo={sth['algorithm']}"
            )


if __name__ == "__main__":
    main()
