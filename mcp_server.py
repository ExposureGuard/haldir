"""
Haldir MCP Server

Exposes Gate, Vault, and Watch as MCP tools for any AI assistant.

Usage:
    HALDIR_API_KEY=your_key python -m haldir.mcp_server
"""

import asyncio
import json
import os
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from haldir_gate import Gate
from haldir_vault import Vault
from haldir_watch import Watch

server = Server("haldir")

# In-memory instances (production would use persistent storage)
gate = Gate(api_key=os.environ.get("HALDIR_API_KEY", ""))
vault = Vault()
watch = Watch()


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # Gate tools
        Tool(
            name="createSession",
            description=(
                "Create an authenticated agent session with scoped permissions. "
                "Returns a session ID that must be passed to all subsequent tool calls. "
                "Scopes control what the agent can do: read, write, spend, execute, browse, send, delete, admin. "
                "Use 'spend:50' to set a $50 budget limit for the session."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Unique identifier for the agent"},
                    "scopes": {"type": "array", "items": {"type": "string"}, "description": "Permission scopes (e.g. ['read', 'browse', 'spend:50'])"},
                    "ttl": {"type": "integer", "description": "Session lifetime in seconds (default 3600)"},
                },
                "required": ["agent_id"],
            },
            annotations={"title": "Create Agent Session", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        ),
        Tool(
            name="checkPermission",
            description="Check if an agent session has a specific permission scope before attempting an action.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "The session ID to check"},
                    "scope": {"type": "string", "description": "The permission to check (e.g. 'write', 'spend', 'delete')"},
                },
                "required": ["session_id", "scope"],
            },
            annotations={"title": "Check Permission", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        ),
        Tool(
            name="revokeSession",
            description="Immediately revoke an agent session, blocking all further actions under that session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "The session ID to revoke"},
                },
                "required": ["session_id"],
            },
            annotations={"title": "Revoke Session", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False},
        ),

        # Vault tools
        Tool(
            name="storeSecret",
            description="Store an encrypted secret (API key, credential, token) in the vault. Secrets are encrypted at rest with AES-256-GCM.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Secret name (e.g. 'stripe_key', 'db_password')"},
                    "value": {"type": "string", "description": "The secret value to encrypt and store"},
                    "scope_required": {"type": "string", "description": "Permission scope needed to access this secret (default: 'read')"},
                },
                "required": ["name", "value"],
            },
            annotations={"title": "Store Secret", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        ),
        Tool(
            name="getSecret",
            description="Retrieve a decrypted secret from the vault. Requires a valid session with the appropriate scope.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Secret name to retrieve"},
                    "session_id": {"type": "string", "description": "Session ID for permission check"},
                },
                "required": ["name", "session_id"],
            },
            annotations={"title": "Get Secret", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        ),
        Tool(
            name="authorizePayment",
            description=(
                "Authorize a payment against an agent's session budget. Checks that the agent has 'spend' permission "
                "and sufficient remaining budget. Does not actually charge — returns an authorization record that the "
                "agent passes to the payment provider."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Session ID of the agent requesting payment"},
                    "amount": {"type": "number", "description": "Amount in USD"},
                    "description": {"type": "string", "description": "What the payment is for"},
                },
                "required": ["session_id", "amount"],
            },
            annotations={"title": "Authorize Payment", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
        ),

        # Watch tools
        Tool(
            name="logAction",
            description="Record an agent action in the immutable audit log. Every tool call, API request, and payment should be logged.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Session ID of the agent"},
                    "tool": {"type": "string", "description": "Which tool or service was used"},
                    "action": {"type": "string", "description": "What action was performed"},
                    "cost_usd": {"type": "number", "description": "Cost of this action in USD (default 0)"},
                },
                "required": ["session_id", "tool", "action"],
            },
            annotations={"title": "Log Action", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        ),
        Tool(
            name="getAuditTrail",
            description="Query the audit log for an agent's actions. Filter by session, agent, tool, or time range. Use for compliance and debugging.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Filter by session ID"},
                    "agent_id": {"type": "string", "description": "Filter by agent ID"},
                    "tool": {"type": "string", "description": "Filter by tool name"},
                    "flagged_only": {"type": "boolean", "description": "Only return flagged entries"},
                },
                "required": [],
            },
            annotations={"title": "Get Audit Trail", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        ),
        Tool(
            name="getSpend",
            description="Get a spend summary for an agent or session. Returns total USD spent and breakdown by tool.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Filter by session ID"},
                    "agent_id": {"type": "string", "description": "Filter by agent ID"},
                },
                "required": [],
            },
            annotations={"title": "Get Spend Summary", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        result = _dispatch(name, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    except PermissionError as e:
        return [TextContent(type="text", text=f"Permission denied: {e}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {type(e).__name__}: {e}")]


def _dispatch(name: str, args: dict) -> dict:
    # Gate
    if name == "createSession":
        session = gate.create_session(
            agent_id=args["agent_id"],
            scopes=args.get("scopes"),
            ttl=args.get("ttl", 3600),
        )
        return {
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "scopes": session.scopes,
            "spend_limit": session.spend_limit,
            "expires_in": int(session.expires_at - session.created_at),
        }

    if name == "checkPermission":
        allowed = gate.check_permission(args["session_id"], args["scope"])
        return {"allowed": allowed, "scope": args["scope"]}

    if name == "revokeSession":
        revoked = gate.revoke_session(args["session_id"])
        return {"revoked": revoked}

    # Vault
    if name == "storeSecret":
        vault.store_secret(args["name"], args["value"], args.get("scope_required", "read"))
        return {"stored": True, "name": args["name"]}

    if name == "getSecret":
        session = gate.get_session(args["session_id"])
        if not session:
            return {"error": "Invalid or expired session"}
        value = vault.get_secret(args["name"], session=session)
        if value is None:
            return {"error": f"Secret '{args['name']}' not found"}
        return {"name": args["name"], "value": value}

    if name == "authorizePayment":
        session = gate.get_session(args["session_id"])
        if not session:
            return {"authorized": False, "reason": "Invalid or expired session"}
        return vault.authorize_payment(session, args["amount"], description=args.get("description", ""))

    # Watch
    if name == "logAction":
        session = gate.get_session(args["session_id"])
        if not session:
            return {"error": "Invalid or expired session"}
        entry = watch.log_action(
            session, tool=args["tool"], action=args["action"],
            cost_usd=args.get("cost_usd", 0.0),
        )
        return {"logged": True, "entry_id": entry.entry_id, "flagged": entry.flagged}

    if name == "getAuditTrail":
        entries = watch.get_audit_trail(
            session_id=args.get("session_id"),
            agent_id=args.get("agent_id"),
            tool=args.get("tool"),
            flagged_only=args.get("flagged_only", False),
        )
        return {"count": len(entries), "entries": [
            {"id": e.entry_id, "agent": e.agent_id, "tool": e.tool,
             "action": e.action, "cost": e.cost_usd, "flagged": e.flagged,
             "timestamp": e.timestamp}
            for e in entries
        ]}

    if name == "getSpend":
        return watch.get_spend(
            session_id=args.get("session_id"),
            agent_id=args.get("agent_id"),
        )

    return {"error": f"Unknown tool: {name}"}


async def _run():
    async with stdio_server() as (read_stream, write_stream):
        init_options = server.create_initialization_options()
        await server.run(read_stream, write_stream, init_options)


def main():
    asyncio.run(_run())


if __name__ == "__main__":
    main()
