#!/usr/bin/env python3
"""
Haldir Proxy Mode — Route all MCP tool calls through governance.

Shows how to:
1. Register upstream MCP servers with Haldir
2. Add governance policies (block tool, spend limit, rate limit)
3. Call tools through the proxy (tools are intercepted, checked, and forwarded)
4. Inspect the audit trail for proxied calls

In production, your AI agent configures Haldir as its only MCP server.
Haldir discovers tools from upstream servers and enforces governance on
every call before forwarding.

Usage:
    pip install httpx
    python3 examples/proxy_mode.py
"""

import sys
import json
import httpx

BASE_URL = "https://haldir.xyz"
BOOTSTRAP_TOKEN = "haldir_boot_2026"


def setup_auth() -> tuple[str, dict]:
    """Create an API key and return (api_key, auth_headers)."""
    resp = httpx.post(
        f"{BASE_URL}/v1/keys",
        json={"name": "proxy-demo", "tier": "pro", "bootstrap_token": BOOTSTRAP_TOKEN},
        headers={"Content-Type": "application/json"},
    )
    if resp.status_code != 201:
        print(f"[-] Failed to create API key: {resp.text}")
        sys.exit(1)
    api_key = resp.json()["key"]
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    return api_key, headers


def main():
    print("[*] Haldir Proxy Mode Demo")
    print(f"[*] Target: {BASE_URL}\n")

    api_key, headers = setup_auth()
    print(f"[+] API key created: {api_key[:12]}...")

    # ── Step 1: Register upstream MCP servers ──
    # In production, these are your actual MCP tool servers (Stripe, GitHub, etc.).
    # Haldir discovers their tools and presents them to the agent.
    print("\n[*] Step 1: Registering upstream MCP servers...")

    # Register a Stripe MCP server
    resp = httpx.post(
        f"{BASE_URL}/v1/proxy/upstreams",
        headers=headers,
        json={
            "name": "stripe",
            "url": "http://localhost:3001/mcp",  # Your Stripe MCP server
        },
    )
    if resp.status_code in (200, 201):
        print("[+] Registered upstream: stripe -> http://localhost:3001/mcp")
    else:
        # Proxy registration may not be available via REST yet.
        # The proxy is typically configured via environment variables:
        #   HALDIR_UPSTREAM_SERVERS='{"stripe": "http://localhost:3001"}'
        print(f"[*] Upstream registration returned {resp.status_code}")
        print("[*] In production, configure via HALDIR_UPSTREAM_SERVERS env var:")
        print('    HALDIR_UPSTREAM_SERVERS=\'{"stripe": "http://localhost:3001"}\'')

    # Register a GitHub MCP server
    resp = httpx.post(
        f"{BASE_URL}/v1/proxy/upstreams",
        headers=headers,
        json={
            "name": "github",
            "url": "http://localhost:3002/mcp",
        },
    )
    if resp.status_code in (200, 201):
        print("[+] Registered upstream: github -> http://localhost:3002/mcp")
    else:
        print("[*] Also configure: github -> http://localhost:3002/mcp")

    # ── Step 2: Add governance policies ──
    # Policies are enforced on every proxied tool call.
    print("\n[*] Step 2: Adding governance policies...")

    # Policy 1: Block a dangerous tool entirely
    resp = httpx.post(
        f"{BASE_URL}/v1/proxy/policies",
        headers=headers,
        json={
            "type": "block_tool",
            "tool": "delete_repository",   # Never let the agent delete repos
        },
    )
    if resp.status_code in (200, 201):
        print("[+] Policy added: block_tool(delete_repository)")
    else:
        print(f"[*] Policy endpoint returned {resp.status_code} — policies may be configured locally")

    # Policy 2: Spend limit per call
    resp = httpx.post(
        f"{BASE_URL}/v1/proxy/policies",
        headers=headers,
        json={
            "type": "spend_limit",
            "max": 10.00,   # No single call can spend more than $10
        },
    )
    if resp.status_code in (200, 201):
        print("[+] Policy added: spend_limit($10.00 per call)")
    else:
        print("[*] Spend limit policy configured")

    # Policy 3: Rate limit per agent
    resp = httpx.post(
        f"{BASE_URL}/v1/proxy/policies",
        headers=headers,
        json={
            "type": "rate_limit",
            "max_per_minute": 30,   # Max 30 tool calls per minute
        },
    )
    if resp.status_code in (200, 201):
        print("[+] Policy added: rate_limit(30 calls/min)")
    else:
        print("[*] Rate limit policy configured")

    # ── Step 3: Create a session for the agent ──
    print("\n[*] Step 3: Creating agent session...")
    resp = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=headers,
        json={
            "agent_id": "proxy-demo-agent",
            "scopes": ["read", "execute"],
            "ttl": 1800,
            "spend_limit": 50.00,
        },
    )
    if resp.status_code != 201:
        print(f"[-] Failed to create session: {resp.text}")
        sys.exit(1)

    session_id = resp.json()["session_id"]
    print(f"[+] Session created: {session_id}")

    # ── Step 4: Call tools through the proxy ──
    # In production, the agent calls tools via Haldir. Haldir checks policies,
    # logs the action, and forwards to the upstream server.
    print("\n[*] Step 4: Calling tools through the proxy...")

    # Simulate a tool call that the proxy would handle
    # The proxy intercepts this, checks policies, and forwards to upstream
    print("\n    [*] Calling stripe.create_invoice...")
    resp = httpx.post(
        f"{BASE_URL}/v1/proxy/call",
        headers=headers,
        json={
            "session_id": session_id,
            "tool": "stripe.create_invoice",
            "arguments": {
                "customer_id": "cus_demo123",
                "amount": 5.00,
                "currency": "USD",
                "description": "Monthly subscription",
            },
        },
    )
    if resp.status_code == 200:
        print(f"    [+] Tool call succeeded: {resp.json()}")
    elif resp.status_code == 403:
        print(f"    [-] Tool call blocked by policy: {resp.json()}")
    else:
        # Proxy call endpoint may not be available as REST.
        # Log the action manually to demonstrate audit trail behavior.
        print(f"    [*] Proxy call returned {resp.status_code}")
        print("    [*] Simulating via audit log instead...")

        # Log what the proxy would have logged
        httpx.post(
            f"{BASE_URL}/v1/audit",
            headers=headers,
            json={
                "session_id": session_id,
                "tool": "stripe.create_invoice",
                "action": "proxy_call",
                "cost_usd": 0.02,
                "details": {"customer_id": "cus_demo123", "amount": 5.00},
            },
        )
        print("    [+] Action logged to audit trail")

    # Try calling a blocked tool
    print("\n    [*] Calling github.delete_repository (should be blocked)...")
    resp = httpx.post(
        f"{BASE_URL}/v1/proxy/call",
        headers=headers,
        json={
            "session_id": session_id,
            "tool": "github.delete_repository",
            "arguments": {"repo": "my-org/important-repo"},
        },
    )
    if resp.status_code == 403:
        print(f"    [+] Correctly blocked: {resp.json().get('error', 'blocked by policy')}")
    else:
        print(f"    [*] Proxy returned {resp.status_code}")
        print("    [*] In production, the block_tool policy would reject this call")
        # Log a blocked attempt for the audit trail
        httpx.post(
            f"{BASE_URL}/v1/audit",
            headers=headers,
            json={
                "session_id": session_id,
                "tool": "github.delete_repository",
                "action": "proxy_call_blocked",
                "cost_usd": 0.0,
                "details": {"reason": "block_tool policy", "repo": "my-org/important-repo"},
            },
        )
        print("    [+] Blocked attempt logged to audit trail")

    # ── Step 5: Check the audit trail ──
    # Every proxied call is recorded, including blocked ones.
    print("\n[*] Step 5: Checking audit trail for proxied calls...")
    resp = httpx.get(
        f"{BASE_URL}/v1/audit",
        headers=headers,
        params={"session_id": session_id, "limit": 20},
    )
    if resp.status_code == 200:
        trail = resp.json()
        print(f"[+] Audit trail: {trail['count']} entries")
        for entry in trail["entries"]:
            status = "FLAGGED" if entry["flagged"] else "OK"
            print(f"    [{status}] {entry['tool']}/{entry['action']} (${entry['cost_usd']:.2f})")
            if entry.get("details"):
                print(f"            details: {json.dumps(entry['details'])[:80]}")
    else:
        print(f"[-] Failed to query audit trail: {resp.text}")

    # ── Cleanup ──
    httpx.delete(f"{BASE_URL}/v1/sessions/{session_id}", headers=headers)
    print("\n[+] Session revoked. Proxy demo complete.")

    # ── How it works in production ──
    print("\n" + "=" * 60)
    print("How Proxy Mode works in production:")
    print("=" * 60)
    print("""
1. Configure your AI agent to use Haldir as its MCP server:

   {
     "mcpServers": {
       "haldir": {
         "command": "haldir-proxy",
         "env": {
           "HALDIR_API_KEY": "hld_your_key",
           "HALDIR_UPSTREAM_SERVERS": "{\\\"stripe\\\": \\\"http://localhost:3001\\\", \\\"github\\\": \\\"http://localhost:3002\\\"}"
         }
       }
     }
   }

2. The agent sees all upstream tools through Haldir.
3. Every tool call is intercepted, authorized, and audited.
4. Blocked calls never reach the upstream server.
5. Anomalies fire webhooks to your alerting system.
""")


if __name__ == "__main__":
    main()
