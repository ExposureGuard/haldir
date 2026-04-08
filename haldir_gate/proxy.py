"""
Haldir Gate — MCP Proxy Mode.

Sits between the AI agent and ALL MCP servers. Every tool call is intercepted,
authorized, audited, and then forwarded. The agent never talks to tools directly.

This is the enforcement layer. Not opt-in. Not cooperative. Mandatory.

Flow:
    Agent → Haldir Proxy → [permission check] → [spend check] → [approval check] → Target MCP Server
                ↓
            [audit log]
                ↓
            [anomaly detection]
                ↓
            [webhook alerts]

The agent configures Haldir as its MCP server. Haldir then proxies requests
to the actual tool servers, enforcing governance on every call.

Config:
{
    "mcpServers": {
        "haldir": {
            "command": "haldir-proxy",
            "env": {
                "HALDIR_API_KEY": "hld_xxx",
                "HALDIR_UPSTREAM_SERVERS": '{"stripe": "http://localhost:3001", "github": "http://localhost:3002"}'
            }
        }
    }
}

The agent sees Haldir's tools. Haldir forwards to the right upstream server
after enforcing all governance rules.
"""

import json
import time
import secrets
import urllib.request
from dataclasses import dataclass, field


@dataclass
class UpstreamServer:
    name: str
    url: str
    tools: list[dict] = field(default_factory=list)
    healthy: bool = True
    last_check: float = 0.0
    total_calls: int = 0
    total_errors: int = 0
    avg_latency_ms: float = 0.0


class HaldirProxy:
    """
    MCP Proxy — intercepts every tool call between agent and upstream servers.

    This is the enforcement layer. The agent connects to Haldir Proxy as its
    only MCP server. Haldir discovers tools from upstream servers, presents them
    to the agent with governance wrappers, and forwards calls after authorization.
    """

    def __init__(self, gate=None, vault=None, watch=None, approval_engine=None,
                 webhook_mgr=None, db_path=None):
        self.gate = gate
        self.vault = vault
        self.watch = watch
        self.approval_engine = approval_engine
        self.webhook_mgr = webhook_mgr
        self._upstreams: dict[str, UpstreamServer] = {}
        self._tool_map: dict[str, str] = {}  # tool_name -> upstream_name
        self._policies: list[dict] = []
        self._db_path = db_path

    def register_upstream(self, name: str, url: str):
        """Register an upstream MCP server to proxy through."""
        server = UpstreamServer(name=name, url=url)
        self._upstreams[name] = server
        # Discover tools from upstream
        self._discover_tools(server)
        return server

    def _discover_tools(self, server: UpstreamServer):
        """Call tools/list on an upstream server to discover its tools."""
        try:
            import httpx
            resp = httpx.post(
                server.url,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                headers={"Content-Type": "application/json"},
                timeout=15,
                follow_redirects=True,
            )
            server._raw_status = resp.status_code
            server._raw_body = resp.text[:500]
            data = resp.json()
            tools = data.get("result", {}).get("tools", [])
            server.tools = tools
            server.healthy = True
            server.last_check = time.time()

            # Map each tool to this upstream
            for tool in tools:
                tool_name = tool["name"]
                namespaced = f"{server.name}.{tool_name}"
                self._tool_map[namespaced] = server.name
                if tool_name not in self._tool_map:
                    self._tool_map[tool_name] = server.name

        except Exception as e:
            server.healthy = False
            server.last_check = time.time()
            server._last_error = str(e)
            import traceback
            traceback.print_exc()

    def add_policy(self, policy_type: str = "", type: str = "", **kwargs):
        """
        Add a governance policy applied to all proxied calls.

        Types:
        - "block_tool": block a specific tool entirely
        - "require_approval": require human approval for specific tools
        - "spend_limit": enforce per-call spend limit
        - "rate_limit": max calls per minute per agent
        - "allow_list": only allow specific tools (deny all others)
        - "deny_list": block specific tools (allow all others)
        - "time_window": only allow calls during specific hours (UTC)
        """
        ptype = policy_type or type
        self._policies.append({"type": ptype, **kwargs})

    def get_tools(self) -> list[dict]:
        """
        Return all discovered tools from all upstream servers.
        Each tool is wrapped with Haldir governance metadata.
        """
        tools = []
        for server in self._upstreams.values():
            if not server.healthy:
                continue
            for tool in server.tools:
                wrapped = dict(tool)
                # Add governance annotations
                wrapped["_haldir"] = {
                    "upstream": server.name,
                    "proxied": True,
                    "governance": "enforced",
                }
                tools.append(wrapped)
        return tools

    def call_tool(self, tool_name: str, arguments: dict,
                  session=None) -> dict:
        """
        Intercept a tool call, enforce governance, then forward to upstream.

        Returns the upstream response or an error if governance blocks the call.
        """
        start_time = time.time()

        # 1. Resolve upstream
        upstream_name = self._tool_map.get(tool_name)
        if not upstream_name:
            return self._error(f"Unknown tool: {tool_name}. Not registered with any upstream server.")

        server = self._upstreams.get(upstream_name)
        if not server or not server.healthy:
            return self._error(f"Upstream server '{upstream_name}' is not healthy.")

        # 2. Session validation
        if not session:
            return self._error("No session provided. Create a session with Haldir Gate first.")
        if not session.is_valid:
            return self._error("Session is invalid or expired.")

        # 3. Permission check
        if not session.has_permission("execute") and not session.has_permission("read"):
            return self._error(f"Session lacks permission to call tools. Scopes: {session.scopes}")

        # 4. Policy enforcement
        policy_result = self._enforce_policies(tool_name, arguments, session)
        if policy_result:
            return policy_result

        # 5. Approval check (if configured)
        if self.approval_engine:
            needs, reason = self.approval_engine.needs_approval(
                tool=upstream_name, action=tool_name,
                amount=float(arguments.get("amount", 0))
            )
            if needs:
                req = self.approval_engine.request_approval(
                    session=session,
                    tool=upstream_name,
                    action=tool_name,
                    reason=reason,
                    details={"arguments": arguments},
                )
                return {
                    "content": [{
                        "type": "text",
                        "text": json.dumps({
                            "status": "approval_required",
                            "request_id": req.request_id,
                            "reason": reason,
                            "message": "This action requires human approval. Poll the approval status or wait for webhook notification.",
                        })
                    }],
                    "isError": False,
                }

        # 6. Forward to upstream
        result = self._forward(server, tool_name, arguments)

        # 7. Audit log
        latency = (time.time() - start_time) * 1000
        server.total_calls += 1
        server.avg_latency_ms = (server.avg_latency_ms * (server.total_calls - 1) + latency) / server.total_calls

        if self.watch and session:
            is_error = result.get("isError", False)
            entry = self.watch.log_action(
                session,
                tool=f"{upstream_name}.{tool_name}",
                action="proxy_call",
                details={
                    "tool": tool_name,
                    "upstream": upstream_name,
                    "latency_ms": round(latency, 1),
                    "error": is_error,
                },
                cost_usd=0.0,
            )

            # 8. Webhook if flagged
            if entry.flagged and self.webhook_mgr:
                self.webhook_mgr.fire_anomaly(
                    agent_id=session.agent_id,
                    tool=f"{upstream_name}.{tool_name}",
                    action="proxy_call",
                    reason=entry.flag_reason,
                )

        return result

    def _forward(self, server: UpstreamServer, tool_name: str,
                 arguments: dict) -> dict:
        """Forward a tool call to the upstream MCP server."""
        actual_tool = tool_name
        if "." in tool_name:
            actual_tool = tool_name.split(".", 1)[1]

        try:
            import httpx
            resp = httpx.post(
                server.url,
                json={
                    "jsonrpc": "2.0",
                    "id": int(time.time() * 1000),
                    "method": "tools/call",
                    "params": {"name": actual_tool, "arguments": arguments},
                },
                headers={"Content-Type": "application/json"},
                timeout=30,
                follow_redirects=True,
            )
            data = resp.json()
            return data.get("result", {"content": [{"type": "text", "text": "Empty response"}]})
        except httpx.HTTPStatusError as e:
            server.total_errors += 1
            return self._error(f"Upstream error: {e.response.status_code}")
        except Exception as e:
            server.total_errors += 1
            server.healthy = False
            return self._error(f"Upstream connection failed: {e}")

    def _enforce_policies(self, tool_name: str, arguments: dict,
                          session) -> dict | None:
        """Check all policies. Returns error dict if blocked, None if allowed."""
        for policy in self._policies:
            ptype = policy["type"]

            if ptype == "block_tool":
                if tool_name == policy.get("tool") or tool_name.endswith(f".{policy.get('tool', '')}"):
                    return self._error(f"Tool '{tool_name}' is blocked by policy.")

            elif ptype == "allow_list":
                allowed = policy.get("tools", [])
                base_name = tool_name.split(".")[-1] if "." in tool_name else tool_name
                if tool_name not in allowed and base_name not in allowed:
                    return self._error(f"Tool '{tool_name}' is not in the allow list.")

            elif ptype == "deny_list":
                denied = policy.get("tools", [])
                base_name = tool_name.split(".")[-1] if "." in tool_name else tool_name
                if tool_name in denied or base_name in denied:
                    return self._error(f"Tool '{tool_name}' is blocked.")

            elif ptype == "spend_limit":
                amount = float(arguments.get("amount", 0))
                if amount > policy.get("max", 0):
                    return self._error(
                        f"Spend ${amount:.2f} exceeds per-call limit ${policy['max']:.2f}")

            elif ptype == "rate_limit":
                # Check recent calls in audit
                if self.watch:
                    one_min_ago = time.time() - 60
                    recent = self.watch.get_audit_trail(
                        agent_id=session.agent_id,
                        since=one_min_ago,
                        limit=int(policy.get("max_per_minute", 60)) + 1,
                    )
                    if len(recent) >= policy.get("max_per_minute", 60):
                        return self._error(
                            f"Rate limit exceeded: {len(recent)} calls in last minute "
                            f"(max {policy['max_per_minute']})")

            elif ptype == "time_window":
                import datetime
                now = datetime.datetime.now(datetime.timezone.utc)
                start_hour = policy.get("start_hour", 0)
                end_hour = policy.get("end_hour", 24)
                if not (start_hour <= now.hour < end_hour):
                    return self._error(
                        f"Tool calls only allowed between {start_hour}:00-{end_hour}:00 UTC. "
                        f"Current time: {now.hour}:{now.minute:02d} UTC")

        return None

    def _error(self, message: str) -> dict:
        return {
            "content": [{"type": "text", "text": json.dumps({"error": message, "blocked_by": "haldir"})}],
            "isError": True,
        }

    def get_stats(self) -> dict:
        """Get proxy statistics for all upstream servers."""
        return {
            "upstreams": {
                name: {
                    "url": s.url,
                    "healthy": s.healthy,
                    "tools": len(s.tools),
                    "total_calls": s.total_calls,
                    "total_errors": s.total_errors,
                    "avg_latency_ms": round(s.avg_latency_ms, 1),
                    "last_check": s.last_check,
                }
                for name, s in self._upstreams.items()
            },
            "total_tools": len(self._tool_map),
            "policies": len(self._policies),
        }
