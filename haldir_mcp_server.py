"""
Haldir MCP stdio server.

Exposes Haldir's governance primitives as MCP tools so any MCP client
(Claude Desktop, Cursor, Windsurf, Claude Code, Cody, or anything
speaking the MCP protocol) can use Haldir natively — scoped sessions,
encrypted secrets, tamper-evident audit log, RFC 6962 proofs, and
signed evidence packs — without writing a line of HTTP glue.

Run directly:

    HALDIR_API_KEY=hld_xxx python -m haldir_mcp_server

Or via the CLI:

    haldir mcp serve

Claude Desktop / Cursor / Windsurf config:

    {
      "mcpServers": {
        "haldir": {
          "command": "haldir",
          "args": ["mcp", "serve"],
          "env": {
            "HALDIR_API_KEY": "hld_your_key",
            "HALDIR_BASE_URL": "https://haldir.xyz"
          }
        }
      }
    }

Transport: stdio (JSON-RPC 2.0 line-delimited). This is the default
MCP transport and the one every major MCP client supports. HTTP/SSE
is a separate endpoint at /mcp on the live API.

Auth: we call the Haldir REST API with the env-sourced API key.
Every MCP tool is a thin wrapper that translates arguments into an
HTTP request and returns the JSON response as MCP TextContent so the
model can reason over the full response body, not just a success flag.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


SERVER_NAME = "haldir"
SERVER_VERSION = "0.3.0"

logger = logging.getLogger("haldir.mcp")


# ── HTTP client ──────────────────────────────────────────────────────

def _base_url() -> str:
    return os.environ.get("HALDIR_BASE_URL", "https://haldir.xyz").rstrip("/")


def _api_key() -> str:
    key = os.environ.get("HALDIR_API_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "HALDIR_API_KEY not set. Mint a key with `haldir init` or "
            "POST /v1/keys, then set it in the MCP server's env block."
        )
    return key


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=_base_url(),
        headers={
            "Authorization": f"Bearer {_api_key()}",
            "Content-Type":  "application/json",
            "User-Agent":    f"haldir-mcp/{SERVER_VERSION}",
        },
        timeout=30.0,
    )


async def _call(method: str, path: str, *,
                 json_body: dict | None = None,
                 params: dict | None = None) -> dict:
    """One-shot REST call. Errors surface as dict with `error` key so
    the model sees what went wrong instead of a silent failure."""
    async with _client() as c:
        try:
            r = await c.request(method, path, json=json_body, params=params)
        except httpx.ConnectError as e:
            return {"error": "connect_error", "message": str(e),
                    "hint": f"Check HALDIR_BASE_URL={_base_url()}"}
        except httpx.TimeoutException:
            return {"error": "timeout", "path": path, "method": method}
    if r.status_code == 204:
        return {"success": True, "status_code": 204}
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text}
    if r.status_code >= 400:
        body.setdefault("error", f"http_{r.status_code}")
        body["status_code"] = r.status_code
    return body


def _text(body: dict) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(body, indent=2))]


# ── Tool registry ────────────────────────────────────────────────────
#
# Each tool maps (name, schema, handler). Handlers are async and
# return the parsed JSON response wrapped as TextContent. Keeping tool
# handlers small + uniform means the model always sees a predictable
# response shape it can reason over.

TOOLS: list[dict[str, Any]] = [
    # ── Gate ──
    {
        "name": "haldir_create_session",
        "description": (
            "Create a scoped Haldir session for an AI agent. Returns a "
            "session_id the agent uses for every subsequent tool call. "
            "Use spend_limit to cap the agent's total spend; scopes "
            "(e.g. ['stripe:refund', 'postgres:read']) gate which "
            "secrets and approvals it can access."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["agent_id"],
            "properties": {
                "agent_id":    {"type": "string", "description": "Human-readable agent identifier"},
                "scopes":      {"type": "array", "items": {"type": "string"}, "description": "Permission scopes"},
                "spend_limit": {"type": "number", "description": "Max USD the session can spend (0 = no limit)"},
                "ttl":         {"type": "integer", "description": "Seconds until the session expires (default 3600)"},
            },
        },
        "handler": lambda args: _call("POST", "/v1/sessions", json_body=args),
    },
    {
        "name": "haldir_get_session",
        "description": "Get a session's current state — remaining budget, scopes, TTL, validity.",
        "inputSchema": {
            "type": "object",
            "required": ["session_id"],
            "properties": {"session_id": {"type": "string"}},
        },
        "handler": lambda args: _call(
            "GET", f"/v1/sessions/{args['session_id']}",
        ),
    },
    {
        "name": "haldir_check_permission",
        "description": (
            "Check whether a session is authorized for a given scope. "
            "Returns {allowed: bool} — call before a risky tool to gate it."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_id", "scope"],
            "properties": {
                "session_id": {"type": "string"},
                "scope":      {"type": "string"},
            },
        },
        "handler": lambda args: _call(
            "POST", f"/v1/sessions/{args['session_id']}/check",
            json_body={"scope": args["scope"]},
        ),
    },
    {
        "name": "haldir_revoke_session",
        "description": "Revoke a session immediately. Idempotent; returns 404 if already gone.",
        "inputSchema": {
            "type": "object",
            "required": ["session_id"],
            "properties": {"session_id": {"type": "string"}},
        },
        "handler": lambda args: _call(
            "DELETE", f"/v1/sessions/{args['session_id']}",
        ),
    },

    # ── Vault ──
    {
        "name": "haldir_store_secret",
        "description": (
            "Store an encrypted secret (API key, token, credential) in "
            "the Vault. AES-256-GCM with AAD binding. scope_required "
            "gates which sessions can later read it."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["name", "value"],
            "properties": {
                "name":            {"type": "string"},
                "value":           {"type": "string"},
                "scope_required":  {"type": "string", "description": "Session scope needed to read this secret"},
            },
        },
        "handler": lambda args: _call("POST", "/v1/secrets", json_body=args),
    },
    {
        "name": "haldir_get_secret",
        "description": (
            "Retrieve a secret by name. Requires a session_id that holds "
            "the secret's scope_required. Returns {value: ...}."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["name", "session_id"],
            "properties": {
                "name":       {"type": "string"},
                "session_id": {"type": "string"},
            },
        },
        "handler": lambda args: _get_secret(args),
    },
    {
        "name": "haldir_list_secrets",
        "description": "List all secret names in this tenant's vault (values never leak).",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda _args: _call("GET", "/v1/secrets"),
    },

    # ── Watch (audit) ──
    {
        "name": "haldir_log_audit_action",
        "description": (
            "Log a tool call to the audit trail. The entry is SHA-256 "
            "hash-chained and leaf-hashed into the tenant's RFC 6962 "
            "Merkle tree so it's retroactively provable."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_id", "tool", "action"],
            "properties": {
                "session_id": {"type": "string"},
                "tool":       {"type": "string", "description": "Tool name (e.g. 'stripe', 'postgres')"},
                "action":     {"type": "string", "description": "Verb (e.g. 'charge', 'read')"},
                "cost_usd":   {"type": "number", "description": "USD charged by this action"},
                "details":    {"type": "object", "description": "Arbitrary JSON metadata"},
            },
        },
        "handler": lambda args: _call("POST", "/v1/audit", json_body=args),
    },
    {
        "name": "haldir_query_audit_trail",
        "description": "Query the audit trail. Filter by agent_id, session_id, tool, flagged.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id":   {"type": "string"},
                "session_id": {"type": "string"},
                "tool":       {"type": "string"},
                "flagged":    {"type": "boolean"},
                "limit":      {"type": "integer", "default": 50},
            },
        },
        "handler": lambda args: _call("GET", "/v1/audit", params=args or None),
    },
    {
        "name": "haldir_verify_audit_chain",
        "description": "Verify the SHA-256 hash chain end-to-end for this tenant's log.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda _args: _call("GET", "/v1/audit/verify"),
    },

    # ── Tamper-evidence (RFC 6962 Merkle) ──
    {
        "name": "haldir_get_tree_head",
        "description": (
            "Get the current Signed Tree Head (STH) for the tenant's "
            "audit log. Returns tree_size, root_hash, signed_at, and "
            "HMAC signature. Auditors pin the STH and demand inclusion "
            "proofs against it later."
        ),
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda _args: _call("GET", "/v1/audit/tree-head"),
    },
    {
        "name": "haldir_get_inclusion_proof",
        "description": (
            "Get an RFC 6962 inclusion proof for a specific audit entry. "
            "Returns audit_path + root_hash + STH that an auditor can "
            "verify offline — no trust in the server needed."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["entry_id"],
            "properties": {"entry_id": {"type": "string"}},
        },
        "handler": lambda args: _call(
            "GET", f"/v1/audit/inclusion-proof/{args['entry_id']}",
        ),
    },
    {
        "name": "haldir_get_consistency_proof",
        "description": (
            "Prove the tree of size `second` is an append-only extension "
            "of the tree of size `first`. Same primitive Certificate "
            "Transparency uses to detect forks in the global WebPKI log."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["first", "second"],
            "properties": {
                "first":  {"type": "integer", "description": "Earlier tree size (>= 1)"},
                "second": {"type": "integer", "description": "Later tree size (>= first)"},
            },
        },
        "handler": lambda args: _call(
            "GET", "/v1/audit/consistency-proof",
            params={"first": args["first"], "second": args["second"]},
        ),
    },

    # ── Approvals ──
    {
        "name": "haldir_request_approval",
        "description": (
            "Request human-in-the-loop approval for a risky action. "
            "Returns an approval_id; poll or webhook until status "
            "becomes 'approved' or 'denied'."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_id", "action", "reason"],
            "properties": {
                "session_id":    {"type": "string"},
                "action":        {"type": "string"},
                "reason":        {"type": "string"},
                "details":       {"type": "object"},
                "expires_in_s":  {"type": "integer", "default": 3600},
            },
        },
        "handler": lambda args: _call(
            "POST", "/v1/approvals/request", json_body=args,
        ),
    },
    {
        "name": "haldir_get_approval_status",
        "description": "Check the current status of an approval request.",
        "inputSchema": {
            "type": "object",
            "required": ["approval_id"],
            "properties": {"approval_id": {"type": "string"}},
        },
        "handler": lambda args: _call(
            "GET", f"/v1/approvals/{args['approval_id']}",
        ),
    },

    # ── Compliance ──
    {
        "name": "haldir_compliance_score",
        "description": (
            "Get the tenant's live audit-prep readiness score (0-100) "
            "with per-criterion pass/warn/fail + remediation hints. "
            "Criteria are relevant to SOC2 Trust Services Criteria "
            "(CC5.2, CC6.1, CC6.7, CC7.2, CC7.3, CC8.1) but this is "
            "NOT a SOC2 attestation."
        ),
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda _args: _call("GET", "/v1/compliance/score"),
    },
    {
        "name": "haldir_build_evidence_pack",
        "description": (
            "Build a signed audit-prep evidence pack for a given period. "
            "Returns JSON with all eight evidence sections + SHA-256 "
            "document signature."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {"type": "string", "description": "ISO 8601 or unix seconds (default: 90d ago)"},
                "until": {"type": "string", "description": "ISO 8601 or unix seconds (default: now)"},
            },
        },
        "handler": lambda args: _call(
            "GET", "/v1/compliance/evidence", params=args or None,
        ),
    },

    # ── Payments ──
    {
        "name": "haldir_authorize_payment",
        "description": (
            "Authorize a payment against a session's spend_limit. "
            "Returns 403 if it would over-run the budget — use this "
            "BEFORE calling the payment provider so the governance "
            "layer gets a chance to block."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_id", "amount"],
            "properties": {
                "session_id":  {"type": "string"},
                "amount":      {"type": "number"},
                "currency":    {"type": "string", "default": "USD"},
                "description": {"type": "string"},
            },
        },
        "handler": lambda args: _call(
            "POST", "/v1/payments/authorize", json_body=args,
        ),
    },
]


async def _get_secret(args: dict[str, Any]) -> dict[str, Any]:
    """get_secret takes the session_id via header, not body. Isolated
    here so we don't have to special-case inside the lambda."""
    name = args["name"]
    session_id = args["session_id"]
    async with _client() as c:
        r = await c.get(
            f"/v1/secrets/{name}",
            headers={"X-Session-ID": session_id},
        )
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text}
    if r.status_code >= 400:
        body.setdefault("error", f"http_{r.status_code}")
        body["status_code"] = r.status_code
    return body


# ── MCP server ───────────────────────────────────────────────────────

def build_server() -> Server:
    """Construct and wire the MCP Server instance. Factored out so
    tests can introspect registered tools without starting stdio."""
    server = Server(SERVER_NAME)
    by_name: dict[str, dict[str, Any]] = {t["name"]: t for t in TOOLS}

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name=t["name"],
                description=t["description"],
                inputSchema=t["inputSchema"],
            )
            for t in TOOLS
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[TextContent]:
        tool = by_name.get(name)
        if tool is None:
            return _text({"error": "unknown_tool", "tool": name})
        try:
            result = await tool["handler"](arguments or {})
        except RuntimeError as e:
            # Typically a missing HALDIR_API_KEY.
            return _text({"error": "config_error", "message": str(e)})
        except Exception as e:
            logger.exception("tool dispatch failed", extra={"tool": name})
            return _text({
                "error":   "dispatch_error",
                "tool":    name,
                "exception": type(e).__name__,
                "message":   str(e),
            })
        return _text(result)

    return server


async def run_stdio() -> None:
    """Run the MCP server over stdio. The MCP client (Claude Desktop
    etc.) spawns this as a subprocess and talks JSON-RPC 2.0 over
    stdin/stdout."""
    server = build_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    """Entry point for `python -m haldir_mcp_server` or
    `haldir mcp serve`."""
    logging.basicConfig(
        stream=sys.stderr,  # MCP uses stdout for protocol; logs go to stderr
        level=os.environ.get("HALDIR_MCP_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    asyncio.run(run_stdio())


if __name__ == "__main__":
    main()
