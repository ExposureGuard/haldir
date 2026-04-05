"""
Haldir MCP Proxy Client — connects Claude Code to tools through Haldir's governance layer.

Usage:
    HALDIR_API_KEY=hld_xxx HALDIR_SESSION_ID=ses_xxx python haldir_mcp_proxy.py
"""

import asyncio
import json
import os

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

HALDIR_URL = os.environ.get("HALDIR_URL", "https://haldir.xyz")
API_KEY = os.environ.get("HALDIR_API_KEY", "")

server = Server("haldir-proxy")

_session_id = None
_tools_cache = None


def _headers():
    return {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}


def _ensure_session():
    global _session_id
    if _session_id:
        return _session_id
    # Create a session automatically
    r = httpx.post(
        f"{HALDIR_URL}/v1/sessions",
        json={"agent_id": "claude-code", "scopes": ["read", "execute", "spend"], "spend_limit": 100},
        headers=_headers(),
    )
    _session_id = r.json()["session_id"]
    return _session_id


def _discover_tools():
    global _tools_cache
    if _tools_cache:
        return _tools_cache
    r = httpx.get(f"{HALDIR_URL}/v1/proxy/tools", headers=_headers())
    _tools_cache = r.json().get("tools", [])
    return _tools_cache


@server.list_tools()
async def list_tools() -> list[Tool]:
    tools = _discover_tools()
    # Also include Haldir's own governance tools
    haldir_tools = [
        Tool(
            name="haldir_check_permission",
            description="Check if the current agent session has a specific permission scope.",
            inputSchema={"type": "object", "properties": {"scope": {"type": "string"}}, "required": ["scope"]},
        ),
        Tool(
            name="haldir_get_spend",
            description="Get spend summary for the current agent session.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="haldir_get_audit",
            description="Get the audit trail for this agent's actions.",
            inputSchema={"type": "object", "properties": {"limit": {"type": "integer", "description": "Max entries to return"}}},
        ),
    ]

    # Convert upstream tools
    for t in tools:
        haldir_tools.append(Tool(
            name=t["name"],
            description=f"[via Haldir] {t.get('description', '')}",
            inputSchema=t.get("inputSchema", {"type": "object", "properties": {}}),
        ))

    return haldir_tools


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    sid = _ensure_session()

    # Haldir governance tools
    if name == "haldir_check_permission":
        r = httpx.post(f"{HALDIR_URL}/v1/sessions/{sid}/check",
                       json={"scope": arguments.get("scope", "read")}, headers=_headers())
        return [TextContent(type="text", text=json.dumps(r.json(), indent=2))]

    if name == "haldir_get_spend":
        r = httpx.get(f"{HALDIR_URL}/v1/audit/spend?agent_id=claude-code", headers=_headers())
        return [TextContent(type="text", text=json.dumps(r.json(), indent=2))]

    if name == "haldir_get_audit":
        limit = arguments.get("limit", 20)
        r = httpx.get(f"{HALDIR_URL}/v1/audit?agent_id=claude-code&limit={limit}", headers=_headers())
        return [TextContent(type="text", text=json.dumps(r.json(), indent=2))]

    # Proxy call — forward through Haldir
    r = httpx.post(
        f"{HALDIR_URL}/v1/proxy/call",
        json={"tool": name, "arguments": arguments, "session_id": sid},
        headers=_headers(),
        timeout=30,
    )
    result = r.json()
    content = result.get("content", [{}])[0].get("text", json.dumps(result))
    return [TextContent(type="text", text=content)]


async def _run():
    async with stdio_server() as (read_stream, write_stream):
        init_options = server.create_initialization_options()
        await server.run(read_stream, write_stream, init_options)


def main():
    # Auto-register upstream if not done
    try:
        httpx.post(
            f"{HALDIR_URL}/v1/proxy/upstreams",
            json={"name": "exposureguard", "url": "https://getexposureguard.com/mcp"},
            headers=_headers(),
            timeout=15,
        )
    except Exception:
        pass
    asyncio.run(_run())


if __name__ == "__main__":
    main()
