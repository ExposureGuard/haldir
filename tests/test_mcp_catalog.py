"""
Catalog invariants for Haldir's MCP tools.

`haldir_mcp_server.TOOLS` is the single source of truth for what Haldir
exposes over MCP. The hosted endpoint is checked against it in
test_mcp_http.py; this file checks the catalog itself, and checks that the
documents which advertise it still tell the truth.

Run: python -m pytest tests/test_mcp_catalog.py -v
"""

from __future__ import annotations

import json
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import haldir_mcp_server  # noqa: E402

TOOLS = haldir_mcp_server.TOOLS
NAMES = [t["name"] for t in TOOLS]


# ── Catalog shape ────────────────────────────────────────────────────

def test_no_duplicate_tool_names() -> None:
    """Two tools with one name means one of them is unreachable — the
    dispatcher builds a dict keyed by name and the later entry wins."""
    dupes = {n for n in NAMES if NAMES.count(n) > 1}
    assert not dupes, f"duplicate tool names: {sorted(dupes)}"


def test_names_are_prefixed_and_snake_case() -> None:
    bad = [n for n in NAMES if not re.fullmatch(r"haldir_[a-z0-9_]+", n)]
    assert not bad, f"tool names must be haldir_snake_case: {bad}"


@pytest.mark.parametrize("tool", TOOLS, ids=NAMES)
def test_schema_is_well_formed(tool: dict) -> None:
    """A schema that requires a property it never declares is rejected by
    strict clients, and silently ignored by lenient ones — either way the
    caller gets a confusing failure instead of a validation message."""
    schema = tool["inputSchema"]
    assert schema["type"] == "object", f"{tool['name']}: inputSchema must be an object"

    props = set(schema.get("properties", {}))
    required = set(schema.get("required", []))
    undeclared = required - props
    assert not undeclared, (
        f"{tool['name']} requires {sorted(undeclared)} but does not declare "
        f"them in properties"
    )


@pytest.mark.parametrize("tool", TOOLS, ids=NAMES)
def test_every_tool_has_a_description_and_handler(tool: dict) -> None:
    assert tool.get("description", "").strip(), f"{tool['name']} has no description"
    assert callable(tool.get("handler")), f"{tool['name']} has no callable handler"


# ── Docs agree with the catalog ──────────────────────────────────────

def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.parametrize("doc", ["README.md", "llms.txt", "CONTRIBUTING.md"])
def test_doc_states_the_current_tool_count(doc: str) -> None:
    """The count is the claim that rots first — it read '10 tools' on three
    documents while the catalog held 19. Anchored on the word 'tools' so
    unrelated numbers elsewhere in the file are ignored."""
    text = _read(doc)
    claims = {int(m) for m in re.findall(r"\b(\d+)\s+tools\b", text)}
    if not claims:
        pytest.skip(f"{doc} makes no tool-count claim")
    assert claims == {len(TOOLS)}, (
        f"{doc} claims {sorted(claims)} tools; the catalog has {len(TOOLS)}"
    )


def test_agent_json_states_the_current_tool_count() -> None:
    """The same claim, in the document agents read for discovery.

    `.well-known/agent.json` said `mcp_stdio.tool_count: 18` while the stdio
    catalog held 19. The prose documents are checked above; this one is not
    prose — it is the machine-readable file an MCP client or a registry
    parses to decide what it will get, and nothing was comparing it to the
    catalog it describes.
    """
    body = json.loads(_read(".well-known/agent.json"))

    # Found by walking rather than by a fixed path, so moving the field in the
    # document does not quietly turn this into a test of nothing.
    found: list[tuple[str, int]] = []

    def walk(node: object, path: str = "") -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "tool_count" and isinstance(value, int):
                    found.append((f"{path}.{key}", value))
                walk(value, f"{path}.{key}")

    walk(body)
    assert found, (
        "agent.json states no tool_count at all — this test needs updating "
        "rather than passing"
    )

    wrong = [(p, v) for p, v in found if v != len(TOOLS)]
    assert not wrong, (
        f"agent.json advertises {wrong}; the catalog has {len(TOOLS)}"
    )


@pytest.mark.parametrize("doc", ["README.md", "llms.txt", "llms-full.txt", "CONTRIBUTING.md"])
def test_docs_do_not_advertise_retired_camel_case_names(doc: str) -> None:
    """The retired names — createSession, getAuditTrail and friends — sent
    callers to a tool that did not exist. They must not creep back into the
    documents, which is where a user copies names from.

    Only backticked and bare identifiers are considered, so the JavaScript
    SDK's own camelCase methods (which are a different, legitimate API)
    are not flagged — they appear in fenced ```js blocks, which are
    stripped before the search.
    """
    text = re.sub(r"```.*?```", "", _read(doc), flags=re.S)  # drop code fences
    retired = {n for n in ("createSession", "getSession", "revokeSession",
                           "checkPermission", "storeSecret", "getSecret",
                           "authorizePayment", "logAction", "getAuditTrail",
                           "getSpend")
               if re.search(rf"\b{re.escape(n)}\b", text)}
    assert not retired, f"{doc} still advertises retired tool names: {sorted(retired)}"
