# How to Secure Any MCP Server with Haldir Proxy Mode

*Published: April 2026 | Tags: MCP security, MCP proxy, MCP server governance, MCP tool permissions, AI agent gateway*

The Model Context Protocol gives AI agents a standardized way to call tools. But MCP has no built-in security. There is no authentication between agent and server. There is no way to restrict which tools an agent can call. There is no rate limiting, no budget enforcement, and no audit trail. Every MCP server is wide open by default.

Haldir proxy mode fixes this. It sits between your agent and any MCP server, intercepting every `tools/call` request. Policies are enforced before the call reaches the upstream. Every action is logged. Sensitive operations can require human approval. Your existing MCP servers do not need to change at all.

This guide walks through the full setup: registering an upstream server, defining policies, making governed calls, and reviewing the audit trail.

## Architecture

```
Agent  -->  Haldir Proxy  -->  Your MCP Server
               |
               +-- Session validation
               +-- Policy enforcement (block, rate limit, spend, time window)
               +-- Audit logging + cost tracking
               +-- Human-in-the-loop (if configured)
```

Your agent talks to Haldir instead of the MCP server directly. Haldir validates the session, checks all policies, forwards the call to the upstream, logs the result, and returns it. The agent and the MCP server are both unaware of the governance layer.

## Step 1: Register Your Upstream MCP Server

Tell Haldir where your MCP server lives. This is a one-time setup per server:

```bash
curl -X POST https://haldir.xyz/v1/proxy/upstreams \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "security-tools",
    "url": "https://my-mcp-server.com/mcp"
  }'
```

Or using the Python SDK:

```python
from haldir import HaldirClient

h = HaldirClient(api_key="hld_xxx")

# Register multiple upstreams if you have several MCP servers
upstreams = [
    ("security-tools", "https://security-mcp.internal/mcp"),
    ("data-tools", "https://data-mcp.internal/mcp"),
    ("comms-tools", "https://comms-mcp.internal/mcp"),
]

for name, url in upstreams:
    h._request("POST", "/v1/proxy/upstreams", json={"name": name, "url": url})
    print(f"Registered upstream: {name}")
```

Haldir discovers the available tools from each upstream automatically. You can verify with:

```bash
curl https://haldir.xyz/v1/proxy/tools \
  -H "Authorization: Bearer hld_xxx"
```

This returns the aggregated tool list from all registered upstreams.

## Step 2: Create a Session for Your Agent

Every agent needs a scoped session. The session defines identity, permissions, budget, and lifetime:

```bash
curl -X POST https://haldir.xyz/v1/sessions \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "research-bot",
    "scopes": ["read", "execute", "spend"],
    "spend_limit": 25.00,
    "ttl": 3600
  }'
```

Response:

```json
{
  "session_id": "ses_a1b2c3d4",
  "agent_id": "research-bot",
  "scopes": ["read", "execute", "spend"],
  "spend_limit": 25.00,
  "expires_at": "2026-04-05T19:00:00Z",
  "ttl": 3600
}
```

The session expires after the TTL. You can revoke it earlier with `DELETE /v1/sessions/ses_a1b2c3d4`.

## Step 3: Add Policies

Policies are rules that the proxy enforces on every tool call. Define them once and they apply automatically. You can combine multiple policy types.

### Block Dangerous Tools

Prevent agents from calling specific tools, regardless of their session scopes:

```bash
curl -X POST https://haldir.xyz/v1/proxy/policies \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "deny",
    "tools": ["delete_database", "drop_table", "send_wire_transfer"]
  }'
```

Any call to a denied tool is blocked immediately and logged with `"status": "denied"`. The agent receives an error response. This is your safety net against the worst-case scenarios.

### Enforce Spend Limits

Cap how much any session can spend. When the limit is reached, all spend-related calls are denied:

```bash
curl -X POST https://haldir.xyz/v1/proxy/policies \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "spend_limit",
    "max_usd": 50.00,
    "per": "session"
  }'
```

This works in conjunction with the per-session `spend_limit` set during session creation. The policy-level limit acts as a global ceiling; the session-level limit acts as a per-agent ceiling. The lower of the two is enforced.

### Rate Limit Tool Calls

Prevent agents from hammering your upstream servers:

```bash
curl -X POST https://haldir.xyz/v1/proxy/policies \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "rate_limit",
    "max_calls": 100,
    "window_seconds": 3600
  }'
```

100 calls per hour. After that, the proxy returns a rate limit error until the window resets. The blocked attempts are still logged so you can see when agents are hitting limits.

### Restrict by Time Window

Allow tool calls only during business hours. Useful for agents that should not operate unattended overnight:

```bash
curl -X POST https://haldir.xyz/v1/proxy/policies \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "time_window",
    "allowed_hours": {"start": "09:00", "end": "17:00"},
    "timezone": "America/New_York"
  }'
```

Calls outside the window are denied and logged. The agent receives a clear error explaining when it can try again.

### Allow List (Whitelist Only Specific Tools)

If you want to be restrictive by default, use an allow list instead of a deny list. Only the listed tools can be called; everything else is blocked:

```bash
curl -X POST https://haldir.xyz/v1/proxy/policies \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "allow",
    "tools": ["scan_domain", "dns_lookup", "whois_lookup", "get_headers"]
  }'
```

This is the safest approach for production deployments. Start with an allow list and expand it as you verify each tool is safe for autonomous use.

## Step 4: Call Tools Through the Proxy

Instead of your agent calling the MCP server directly, route calls through Haldir:

```bash
curl -X POST https://haldir.xyz/v1/proxy/call \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "scan_domain",
    "arguments": {"domain": "example.com"},
    "session_id": "ses_a1b2c3d4"
  }'
```

The proxy validates the session, checks all policies (deny list, allow list, rate limit, spend limit, time window), forwards the call to the correct upstream, logs the result, and returns it. One extra hop, full governance.

Using the Python SDK:

```python
from haldir import HaldirClient

h = HaldirClient(api_key="hld_xxx")

session = h.create_session(
    agent_id="scanner-bot",
    scopes=["read", "execute"],
    spend_limit=10.00,
    ttl=1800
)

# Call through the proxy — governance is automatic
result = h._request("POST", "/v1/proxy/call", json={
    "tool": "scan_domain",
    "arguments": {"domain": "example.com"},
    "session_id": session["session_id"]
})

print(result)
```

## Step 5: Review the Audit Trail

Every proxied call generates an audit entry, whether it was allowed or blocked:

```python
# Get the audit trail for this session
trail = h.get_audit_trail(session_id=session["session_id"])

for entry in trail["entries"]:
    status = "DENIED" if entry.get("flagged") else "OK"
    print(f"{entry['timestamp']} | {entry['tool']} | {status} | ${entry['cost_usd']:.2f}")

# Spend summary
spend = h.get_spend(session_id=session["session_id"])
print(f"\nTotal spend: ${spend['total_usd']:.2f}")
```

Blocked calls are logged with `flagged: true` and include the policy that triggered the denial. This is how you debug agent behavior, tune your policies, and produce compliance reports.

```json
{
  "timestamp": "2026-04-05T14:32:01Z",
  "session_id": "ses_a1b2c3d4",
  "agent_id": "scanner-bot",
  "tool": "delete_database",
  "status": "denied",
  "flagged": true,
  "flag_reason": "Tool 'delete_database' is on the deny list",
  "cost_usd": 0.00
}
```

You can see exactly when the agent tried to call a blocked tool, and the flag reason tells you which policy stopped it.

## Using Haldir Proxy with Claude Code

Haldir ships as an MCP server itself. Add it to your Claude Code configuration and every tool call from Claude goes through the proxy:

```json
{
  "mcpServers": {
    "haldir-proxy": {
      "command": "python",
      "args": ["/path/to/haldir_mcp_proxy.py"],
      "env": {
        "HALDIR_API_KEY": "hld_xxx",
        "HALDIR_URL": "https://haldir.xyz"
      }
    }
  }
}
```

Claude Code sees the proxied tools alongside Haldir's own governance tools (`haldir_check_permission`, `haldir_get_spend`, `haldir_get_audit`). The agent can query its own permissions and spend in real time.

## Combining Policies

Policies stack. You can combine all of them for defense in depth:

1. **Allow list** limits which tools can be called at all
2. **Deny list** blocks specific dangerous tools as a safety net
3. **Spend limit** caps the total cost per session
4. **Rate limit** prevents runaway loops
5. **Time window** restricts when agents can operate

A call must pass all active policies to reach the upstream. If any policy denies it, the call is blocked and logged.

## Getting Started

```bash
pip install haldir
```

Register your first upstream, create a session, add a policy, and make a proxied call. Full agent governance in five minutes, no changes to your existing MCP servers.

Docs: [haldir.xyz/docs](https://haldir.xyz/docs) | Source: [GitHub](https://github.com/ExposureGuard/haldir) | MCP config: [Smithery](https://smithery.ai/server/haldir/haldir)

---

*Haldir is the MCP-native governance layer for AI agents. Proxy mode intercepts every tool call so your MCP servers do not need to implement security themselves. Start free at [haldir.xyz](https://haldir.xyz).*
