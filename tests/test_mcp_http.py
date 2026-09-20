"""
Tests for the hosted MCP endpoint — POST /mcp.

This surface had no tests at all. The agent-discovery suites check the
`.well-known/mcp/*` manifests, which describe the endpoint, but nothing ever
called it — which is how it came to advertise a different tool set, under
different names, from the stdio server shipped in the same repository.

The cross-surface test at the bottom is the point of the file: every name
this endpoint advertises must exist in the canonical catalog
(`haldir_mcp_server.TOOLS`), so the two can't drift apart again.

Run: python -m pytest tests/test_mcp_http.py -v
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import haldir_mcp_server  # noqa: E402


def rpc(client, key, method, params=None, req_id=1):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": req_id,
                                  "method": method, "params": params or {}},
                    headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200, r.data
    return r.get_json()


@pytest.fixture
def mcp(haldir_client, bootstrap_key, fresh_counter):
    return haldir_client, bootstrap_key


# ── Protocol shape ───────────────────────────────────────────────────

def test_initialize_handshake(mcp) -> None:
    client, key = mcp
    body = rpc(client, key, "initialize",
               {"protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"}})
    result = body["result"]
    assert result["protocolVersion"]
    assert "tools" in result["capabilities"]
    assert result["serverInfo"]["name"] == "haldir"


def test_tools_list_returns_tools(mcp) -> None:
    client, key = mcp
    tools = rpc(client, key, "tools/list")["result"]["tools"]
    assert tools, "the endpoint advertised no tools"
    for t in tools:
        assert t["name"] and t["description"]
        assert t["inputSchema"]["type"] == "object"


def test_unknown_method_is_a_jsonrpc_error(mcp) -> None:
    client, key = mcp
    body = rpc(client, key, "does/not/exist")
    assert body["error"]["code"] == -32601
    assert "not found" in body["error"]["message"].lower()


def test_unknown_tool_is_an_iserror_result(mcp) -> None:
    """Not a transport error — MCP expects the model to see it and adapt."""
    client, key = mcp
    result = rpc(client, key, "tools/call",
                 {"name": "haldir_not_a_real_tool", "arguments": {}})["result"]
    assert result["isError"] is True
    assert "unknown tool" in result["content"][0]["text"].lower()


# ── Tools actually work ──────────────────────────────────────────────

def test_tool_call_creates_a_session(mcp) -> None:
    client, key = mcp
    result = rpc(client, key, "tools/call",
                 {"name": "haldir_create_session",
                  "arguments": {"agent_id": "mcp-http-bot"}})["result"]
    assert not result.get("isError"), result
    payload = json.loads(result["content"][0]["text"])
    assert payload["session_id"].startswith("ses_")
    assert payload["agent_id"] == "mcp-http-bot"


def test_tool_call_checks_a_permission(mcp) -> None:
    client, key = mcp
    created = rpc(client, key, "tools/call",
                  {"name": "haldir_create_session",
                   "arguments": {"agent_id": "mcp-perm-bot",
                                 "scopes": ["read"]}})["result"]
    sid = json.loads(created["content"][0]["text"])["session_id"]

    allowed = rpc(client, key, "tools/call",
                  {"name": "haldir_check_permission",
                   "arguments": {"session_id": sid, "scope": "read"}})["result"]
    assert not allowed.get("isError")
    assert json.loads(allowed["content"][0]["text"])["allowed"] is True


# ── The cross-surface guard ──────────────────────────────────────────

def test_every_advertised_tool_exists_in_the_canonical_catalog(mcp) -> None:
    """The two MCP surfaces in this repository must agree.

    They did not: this endpoint served ten camelCase tools while
    haldir_mcp_server served eighteen haldir_-prefixed ones, and llms.txt
    documented one naming scheme while llms-full.txt documented the other.
    Anyone following the wrong document got an unknown-tool error.

    The stdio server's catalog is the single source of truth. This endpoint
    may expose a subset — it implements what it implements — but never a
    name that is not in that catalog.
    """
    client, key = mcp
    advertised = {t["name"] for t in rpc(client, key, "tools/list")["result"]["tools"]}
    canonical = {t["name"] for t in haldir_mcp_server.TOOLS}

    unknown = advertised - canonical
    assert not unknown, (
        f"POST /mcp advertises tools that are not in the canonical catalog: "
        f"{sorted(unknown)}"
    )


def test_advertised_names_are_not_camel_case(mcp) -> None:
    """A second guard on the same mistake: the catalog is snake_case with a
    haldir_ prefix, and a camelCase name means someone added a tool here
    instead of there."""
    client, key = mcp
    names = [t["name"] for t in rpc(client, key, "tools/list")["result"]["tools"]]
    bad = [n for n in names if any(c.isupper() for c in n)]
    assert not bad, f"camelCase tool names on the HTTP surface: {bad}"
