"""
Tests for haldir_mcp_server — the MCP stdio surface.

Scope:
  - Tool registry: every tool in TOOLS has the shape MCP expects
    (name, description, inputSchema, handler) and the schema is
    valid JSONSchema (type=object + required-in-properties).
  - Handler dispatch: calling a known tool returns a structured
    response; unknown tools return a well-formed error; handler
    exceptions are caught and surfaced as dispatch_error.
  - Config / env:
      - Missing HALDIR_API_KEY raises a clear RuntimeError that the
        server turns into a config_error MCP response, not a crash.
      - HALDIR_BASE_URL is honored + normalized (trailing slash stripped).
  - Integration: the full request/response cycle over an injected
    fake httpx transport — proves create_session maps to POST
    /v1/sessions with the correct body and bearer auth.

Run: python -m pytest tests/test_mcp_server.py -v
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
import httpx  # noqa: E402

import haldir_mcp_server as mcp_server  # noqa: E402


# ── Registry shape ───────────────────────────────────────────────────

def test_tool_registry_is_non_empty() -> None:
    assert len(mcp_server.TOOLS) >= 15, (
        "expected the full Haldir primitive surface to be exposed"
    )


def test_every_tool_has_required_fields() -> None:
    for t in mcp_server.TOOLS:
        assert t["name"].startswith("haldir_"), (
            f"tool name {t['name']!r} must be haldir-prefixed so it "
            "doesn't collide with other MCP servers in the same client"
        )
        assert isinstance(t["description"], str) and len(t["description"]) > 30
        schema = t["inputSchema"]
        assert schema["type"] == "object"
        # Every required field must also appear in properties.
        required = schema.get("required", [])
        props = schema.get("properties", {})
        for r in required:
            assert r in props, (
                f"tool {t['name']} lists {r!r} as required but not in properties"
            )
        # Handler must be callable (async or sync).
        assert callable(t["handler"])


def test_tool_names_are_unique() -> None:
    names = [t["name"] for t in mcp_server.TOOLS]
    assert len(names) == len(set(names))


def test_critical_surface_is_exposed() -> None:
    """If an MCP client can't see these, Haldir isn't really a
    governance layer for that client — regression-guard the set."""
    names = {t["name"] for t in mcp_server.TOOLS}
    must_have = {
        "haldir_create_session",
        "haldir_check_permission",
        "haldir_log_audit_action",
        "haldir_get_tree_head",
        "haldir_get_inclusion_proof",
        "haldir_get_consistency_proof",
        "haldir_compliance_score",
        "haldir_build_evidence_pack",
        "haldir_store_secret",
        "haldir_get_secret",
    }
    missing = must_have - names
    assert not missing, f"MCP server is missing critical tools: {missing}"


# ── Server construction ──────────────────────────────────────────────

def test_build_server_returns_configured_instance() -> None:
    server = mcp_server.build_server()
    # The MCP Server class exposes a .name — pin it to our advertised name.
    assert server.name == mcp_server.SERVER_NAME


# ── Env + config ─────────────────────────────────────────────────────

def test_missing_api_key_raises_clear_error(monkeypatch) -> None:
    monkeypatch.delenv("HALDIR_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="HALDIR_API_KEY"):
        mcp_server._api_key()


def test_base_url_strips_trailing_slash(monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_BASE_URL", "https://haldir.xyz/")
    assert mcp_server._base_url() == "https://haldir.xyz"


def test_base_url_defaults_to_production(monkeypatch) -> None:
    monkeypatch.delenv("HALDIR_BASE_URL", raising=False)
    assert mcp_server._base_url() == "https://haldir.xyz"


# ── Handler dispatch ─────────────────────────────────────────────────

class _FakeTransport(httpx.AsyncBaseTransport):
    """Captures the outbound request + returns a canned response.
    Lets us prove the MCP tool wrapper maps to the right REST call
    without booting the Flask app."""

    def __init__(self, status: int = 200, body: dict | None = None):
        self.status = status
        self.body = body if body is not None else {"ok": True}
        self.captured: httpx.Request | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.captured = request
        return httpx.Response(
            status_code=self.status,
            content=json.dumps(self.body).encode(),
            headers={"Content-Type": "application/json"},
            request=request,
        )


@pytest.mark.asyncio
async def test_create_session_maps_to_rest(monkeypatch) -> None:
    import haldir_mcp_server as m
    monkeypatch.setenv("HALDIR_API_KEY", "hld_test_key_001")
    monkeypatch.setenv("HALDIR_BASE_URL", "https://test.haldir.xyz")

    fake = _FakeTransport(
        status=201,
        body={"session_id": "ses_abc", "agent_id": "refund-bot", "spend_limit": 50.0},
    )

    def client_with_fake() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=m._base_url(),
            headers={"Authorization": f"Bearer {m._api_key()}"},
            transport=fake,
            timeout=5.0,
        )
    monkeypatch.setattr(m, "_client", client_with_fake)

    tool = next(t for t in m.TOOLS if t["name"] == "haldir_create_session")
    result = await tool["handler"]({
        "agent_id":    "refund-bot",
        "scopes":      ["stripe:refund"],
        "spend_limit": 50.0,
    })

    # Round-trip: got the canned response.
    assert result["session_id"] == "ses_abc"

    # The outbound request went where we expected, with the right auth.
    assert fake.captured is not None
    req = fake.captured
    assert req.method == "POST"
    assert req.url.path == "/v1/sessions"
    assert req.headers["Authorization"] == "Bearer hld_test_key_001"
    body = json.loads(bytes(req.content))
    assert body["agent_id"] == "refund-bot"
    assert body["scopes"] == ["stripe:refund"]


@pytest.mark.asyncio
async def test_http_error_surfaces_as_error_key(monkeypatch) -> None:
    import haldir_mcp_server as m
    monkeypatch.setenv("HALDIR_API_KEY", "hld_test_key_001")

    fake = _FakeTransport(status=403, body={"error": "Agent limit reached"})

    def client_with_fake() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=m._base_url(),
            headers={"Authorization": f"Bearer {m._api_key()}"},
            transport=fake,
            timeout=5.0,
        )
    monkeypatch.setattr(m, "_client", client_with_fake)

    tool = next(t for t in m.TOOLS if t["name"] == "haldir_create_session")
    result = await tool["handler"]({"agent_id": "bot"})
    assert result.get("status_code") == 403
    assert "error" in result


# ── MCP dispatch wrapper ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unknown_tool_returns_structured_error(monkeypatch) -> None:
    import haldir_mcp_server as m
    monkeypatch.setenv("HALDIR_API_KEY", "hld_x")
    server = m.build_server()
    # Reach into the dispatcher the same way the stdio transport does.
    # MCP's Server registers handlers keyed by method; pull the call_tool.
    handlers = server.request_handlers
    # call_tool's request type is CallToolRequest; find it by type name.
    call_type = next(
        t for t in handlers if t.__name__.endswith("CallToolRequest")
    )
    handler = handlers[call_type]
    from mcp.types import CallToolRequest
    req = CallToolRequest(
        method="tools/call",
        params={"name": "haldir_not_a_real_tool", "arguments": {}},
    )
    resp = await handler(req)
    # Low-level protocol result has a .root with the .content list.
    result_obj = resp.root if hasattr(resp, "root") else resp
    content = result_obj.content
    text = content[0].text
    body = json.loads(text)
    assert body["error"] == "unknown_tool"
    assert body["tool"] == "haldir_not_a_real_tool"


# ── CLI integration ─────────────────────────────────────────────────

def test_cli_mcp_config_command_prints_valid_snippet(capsys, monkeypatch) -> None:
    """`haldir mcp config` must print a snippet that's (a) valid JSON
    and (b) has the mcpServers.haldir.command / args / env shape every
    MCP client expects."""
    import cli
    monkeypatch.setenv("HALDIR_API_KEY", "hld_test_cfg")
    monkeypatch.setenv("HALDIR_BASE_URL", "https://test.haldir.xyz")

    # Fabricate a Namespace — the command ignores its args.
    import argparse
    cli.cmd_mcp_config(argparse.Namespace())
    out = capsys.readouterr().out

    # Find the JSON block (everything up to the blank line before the
    # informational text).
    json_block = out.split("\n\n", 1)[0]
    cfg = json.loads(json_block)
    assert "mcpServers" in cfg
    haldir_entry = cfg["mcpServers"]["haldir"]
    assert haldir_entry["command"] == "haldir"
    assert haldir_entry["args"] == ["mcp", "serve"]
    assert haldir_entry["env"]["HALDIR_API_KEY"] == "hld_test_cfg"
    assert haldir_entry["env"]["HALDIR_BASE_URL"] == "https://test.haldir.xyz"
