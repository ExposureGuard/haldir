#!/usr/bin/env python3
"""
Haldir Quickstart — Full lifecycle demo.

Covers: API key creation, sessions, secrets, payments, audit logging,
spend tracking, and session revocation. Run against https://haldir.xyz.

Usage:
    pip install httpx
    python3 examples/quickstart.py
"""

import os
import sys
import httpx

BASE_URL = "https://haldir.xyz"
BOOTSTRAP_TOKEN = os.environ.get("HALDIR_BOOTSTRAP_TOKEN", "")
HEADERS = {"Content-Type": "application/json"}


def main():
    print("[*] Haldir Quickstart")
    print(f"[*] Target: {BASE_URL}\n")

    # ── Step 1: Create an API key ──
    # The bootstrap token lets you create your first key without existing auth.
    print("[*] Step 1: Creating API key...")
    resp = httpx.post(
        f"{BASE_URL}/v1/keys",
        headers=HEADERS,
        json={
            "name": "quickstart-demo",
            "bootstrap_token": BOOTSTRAP_TOKEN,
        },
    )
    if resp.status_code != 201:
        print(f"[-] Failed to create API key: {resp.text}")
        sys.exit(1)

    api_key = resp.json()["key"]
    print(f"[+] API key created: {api_key[:12]}...")

    # All subsequent requests use this key for auth
    auth_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    # ── Step 2: Create an agent session ──
    # Sessions are scoped, time-limited, and optionally budget-capped.
    print("\n[*] Step 2: Creating agent session...")
    resp = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=auth_headers,
        json={
            "agent_id": "demo-agent",
            "scopes": ["read", "write", "execute"],
            "ttl": 3600,            # 1 hour
            "spend_limit": 25.00,   # $25 budget cap
        },
    )
    if resp.status_code != 201:
        print(f"[-] Failed to create session: {resp.text}")
        sys.exit(1)

    session = resp.json()
    session_id = session["session_id"]
    print(f"[+] Session created: {session_id}")
    print(f"    Scopes: {session['scopes']}")
    print(f"    Spend limit: ${session['spend_limit']}")

    # ── Step 3: Store a secret ──
    # Vault encrypts secrets at rest. Retrieval can be scoped to sessions.
    print("\n[*] Step 3: Storing a secret in the vault...")
    resp = httpx.post(
        f"{BASE_URL}/v1/secrets",
        headers=auth_headers,
        json={
            "name": "demo_api_token",
            "value": "sk-live-abc123def456",
            "scope_required": "read",   # session needs "read" scope to retrieve
        },
    )
    if resp.status_code == 201:
        print(f"[+] Secret stored: {resp.json()['name']}")
    else:
        print(f"[-] Failed to store secret: {resp.text}")

    # ── Step 4: Retrieve the secret ──
    # Pass X-Session-ID to enforce scope checks.
    print("\n[*] Step 4: Retrieving secret (with session scope check)...")
    resp = httpx.get(
        f"{BASE_URL}/v1/secrets/demo_api_token",
        headers={**auth_headers, "X-Session-ID": session_id},
    )
    if resp.status_code == 200:
        value = resp.json()["value"]
        print(f"[+] Secret retrieved: {value[:8]}...{value[-4:]}")
    else:
        print(f"[-] Failed to retrieve secret: {resp.text}")

    # ── Step 5: Authorize a payment ──
    # Charges against the session's spend limit. Fails if budget exceeded.
    print("\n[*] Step 5: Authorizing a $4.50 payment...")
    resp = httpx.post(
        f"{BASE_URL}/v1/payments/authorize",
        headers=auth_headers,
        json={
            "session_id": session_id,
            "amount": 4.50,
            "currency": "USD",
            "description": "GPT-4 API call for summarization",
        },
    )
    result = resp.json()
    if result.get("authorized"):
        print(f"[+] Payment authorized: ${result['amount']}")
        print(f"    Remaining budget: ${result['remaining_budget']:.2f}")
    else:
        print(f"[-] Payment denied: {result.get('reason', resp.text)}")

    # ── Step 6: Log an action to the audit trail ──
    # Every agent action should be logged for compliance and anomaly detection.
    print("\n[*] Step 6: Logging an action...")
    resp = httpx.post(
        f"{BASE_URL}/v1/audit",
        headers=auth_headers,
        json={
            "session_id": session_id,
            "tool": "openai",
            "action": "chat_completion",
            "cost_usd": 0.03,
            "details": {
                "model": "gpt-4",
                "tokens": 1500,
                "prompt": "Summarize Q3 earnings...",
            },
        },
    )
    if resp.status_code == 201:
        entry = resp.json()
        print(f"[+] Action logged: {entry['entry_id']}")
        if entry.get("flagged"):
            print(f"    [!] FLAGGED: {entry['flag_reason']}")
    else:
        print(f"[-] Failed to log action: {resp.text}")

    # ── Step 7: Query the audit trail ──
    # Filter by session, agent, tool, or flagged-only.
    print("\n[*] Step 7: Querying audit trail...")
    resp = httpx.get(
        f"{BASE_URL}/v1/audit",
        headers=auth_headers,
        params={"session_id": session_id, "limit": 10},
    )
    if resp.status_code == 200:
        trail = resp.json()
        print(f"[+] Audit trail: {trail['count']} entries")
        for entry in trail["entries"]:
            flag = " [FLAGGED]" if entry["flagged"] else ""
            print(f"    - {entry['tool']}/{entry['action']} (${entry['cost_usd']:.2f}){flag}")
    else:
        print(f"[-] Failed to query audit trail: {resp.text}")

    # ── Step 8: Get spend summary ──
    # Aggregated spend by tool, useful for cost dashboards.
    print("\n[*] Step 8: Getting spend summary...")
    resp = httpx.get(
        f"{BASE_URL}/v1/audit/spend",
        headers=auth_headers,
        params={"session_id": session_id},
    )
    if resp.status_code == 200:
        spend = resp.json()
        print(f"[+] Total spend: ${spend.get('total_usd', 0):.2f}")
        for tool, amount in spend.get("by_tool", {}).items():
            print(f"    - {tool}: ${amount:.2f}")
    else:
        print(f"[-] Failed to get spend: {resp.text}")

    # ── Step 9: Revoke the session ──
    # Immediately invalidates the session. No further actions can use it.
    print("\n[*] Step 9: Revoking session...")
    resp = httpx.delete(
        f"{BASE_URL}/v1/sessions/{session_id}",
        headers=auth_headers,
    )
    if resp.status_code == 200:
        print(f"[+] Session revoked: {session_id}")
    else:
        print(f"[-] Failed to revoke session: {resp.text}")

    # Verify session is dead
    resp = httpx.get(
        f"{BASE_URL}/v1/sessions/{session_id}",
        headers=auth_headers,
    )
    if resp.status_code == 404:
        print("[+] Confirmed: session no longer valid")
    else:
        session_info = resp.json()
        print(f"[*] Session status: valid={session_info.get('is_valid')}")

    # ── Cleanup: delete the demo secret ──
    httpx.delete(f"{BASE_URL}/v1/secrets/demo_api_token", headers=auth_headers)

    print("\n[+] Quickstart complete. Full lifecycle demonstrated.")
    print("[*] Docs: https://haldir.xyz/docs")


if __name__ == "__main__":
    main()
