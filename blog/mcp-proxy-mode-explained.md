# MCP Proxy Mode: How to Intercept Every AI Agent Tool Call

*Published: April 2026 | Tags: MCP proxy, MCP gateway, agent tool call interception, MCP security*

The Model Context Protocol (MCP) gives AI agents a standardized way to call tools. But MCP has no built-in governance. Any agent with access to an MCP server can call any tool, with any arguments, as many times as it wants. There is no authentication, no rate limiting, no policy enforcement, and no audit trail at the protocol level.

Haldir's **proxy mode** fixes this. It sits between your agent and your MCP servers, intercepting every tool call before it reaches the upstream. Policies are enforced. Actions are logged. Sensitive operations require human approval. Your tools never know the difference.

## What Is an MCP Proxy?

An MCP proxy is a gateway that intercepts the `tools/call` request in the MCP protocol. Instead of your agent talking directly to an MCP server, it talks to the proxy. The proxy:

1. **Authenticates** the request (API key + session validation)
2. **Checks policies** (is this tool allowed? is the agent within budget? is this within the time window?)
3. **Requests approval** if the action triggers a human-in-the-loop rule
4. **Forwards** the call to the upstream MCP server
5. **Logs** the call, response, latency, and cost to the audit trail
6. **Returns** the result to the agent

The agent's experience is unchanged. It calls tools the same way. But every call now passes through a governance checkpoint.

```
Agent  ──>  Haldir Proxy  ──>  Upstream MCP Server
               │
               ├── Auth check
               ├── Policy enforcement
               ├── Approval (if required)
               ├── Audit logging
               └── Cost tracking
```

## Setting Up the Proxy

### Step 1: Register Your Upstream MCP Server

Tell Haldir where your actual MCP server lives:

```bash
curl -X POST https://haldir.xyz/v1/proxy/upstreams \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-tools",
    "url": "https://my-mcp-server.com/mcp"
  }'
```

### Step 2: Create a Session for Your Agent

Every agent needs a scoped session. This is how the proxy knows what the agent is allowed to do:

```bash
curl -X POST https://haldir.xyz/v1/sessions \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "research-bot",
    "scopes": ["read", "browse", "spend:25"],
    "ttl": 3600
  }'
```

Response:

```json
{
  "session_id": "ses_a1b2c3d4",
  "agent_id": "research-bot",
  "scopes": ["read", "browse", "spend:25"],
  "expires_at": "2026-04-05T19:00:00Z"
}
```

### Step 3: Call Tools Through the Proxy

Instead of calling your MCP server directly, call through Haldir:

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

The proxy validates the session, checks policies, forwards to the upstream, logs the result, and returns it. One extra hop, full governance.

### Step 4: List Available Tools

See what tools are available through the proxy (aggregated from all registered upstreams):

```bash
curl https://haldir.xyz/v1/proxy/tools \
  -H "Authorization: Bearer hld_xxx"
```

## Policy Types

Policies are the rules the proxy enforces. You define them once, and every tool call is checked automatically.

### Allow List

Only permit specific tools:

```bash
curl -X POST https://haldir.xyz/v1/proxy/policies \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "allow",
    "tools": ["scan_domain", "dns_lookup", "whois_lookup"]
  }'
```

Any tool call not on the allow list is blocked and logged.

### Deny List

Block specific dangerous tools while allowing everything else:

```bash
curl -X POST https://haldir.xyz/v1/proxy/policies \
  -H "Authorization: Bearer hld_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "deny",
    "tools": ["delete_database", "send_email", "transfer_funds"]
  }'
```

### Spend Limit

Enforce a maximum spend per session. Once the budget is exhausted, all spend-related tool calls are denied:

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

### Rate Limit

Prevent agents from hammering tools:

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

### Time Window

Restrict tool access to business hours:

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

## Using the Proxy with the Python SDK

The SDK makes proxy calls feel native:

```python
from haldir import HaldirClient

h = HaldirClient(api_key="hld_xxx")

# Register upstream
h.register_upstream("security-tools", "https://my-mcp-server.com/mcp")

# Create session
session = h.create_session("my-agent", scopes=["read", "spend:25"])

# Call through proxy — governance is automatic
result = h.proxy_call(
    tool="scan_domain",
    arguments={"domain": "example.com"},
    session_id=session["session_id"]
)

print(result)
```

Every call through `proxy_call` is authenticated, policy-checked, and logged. You get the full audit trail without writing any governance code yourself.

## What Gets Logged

Every proxied call generates an audit entry:

```json
{
  "timestamp": "2026-04-05T14:32:01Z",
  "session_id": "ses_a1b2c3d4",
  "agent_id": "research-bot",
  "tool": "scan_domain",
  "arguments": {"domain": "example.com"},
  "upstream": "security-tools",
  "status": "allowed",
  "latency_ms": 342,
  "cost_usd": 0.00
}
```

Blocked calls are logged too, with `"status": "denied"` and the policy that triggered the denial. This is how you debug agent behavior and build compliance reports.

## Why Not Just Wrap Your Tools?

You could write governance logic inside each tool. Check permissions in every handler. Log manually. Enforce budgets in application code. Teams try this and it fails for three reasons:

1. **It does not scale.** Every new tool needs the same boilerplate. Miss one and you have a gap.
2. **It is not centralized.** Policies are scattered across codebases. No single view of what agents are doing.
3. **It cannot be audited.** Compliance teams need a single, immutable log. Not grep across 30 microservices.

The proxy approach gives you one enforcement point, one policy engine, and one audit trail. Add a new upstream and governance applies automatically.

## Getting Started

```bash
pip install haldir
```

Register your first upstream, create a session, and make a proxied call. Five minutes to full agent governance.

Docs: [haldir.xyz/docs](https://haldir.xyz/docs) | Source: [GitHub](https://github.com/ExposureGuard/haldir) | MCP config: [Smithery](https://smithery.ai/server/haldir/haldir)

---

*Haldir is the MCP-native governance layer for AI agents. Proxy mode intercepts every tool call so you do not have to. Start free at [haldir.xyz](https://haldir.xyz).*
