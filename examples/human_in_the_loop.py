#!/usr/bin/env python3
"""
Haldir Human-in-the-Loop — Approval workflow demo.

Shows how to:
1. Add approval rules (spend thresholds, tool restrictions)
2. Request human approval for sensitive actions
3. Poll for approval status (agent side)
4. Approve or deny requests (human side)
5. Proceed based on the decision

This is the workflow that makes enterprises trust AI agents with real actions.
No other MCP governance layer has this.

Usage:
    pip install httpx
    python3 examples/human_in_the_loop.py
"""

import os
import sys
import time
import httpx

BASE_URL = "https://haldir.xyz"
BOOTSTRAP_TOKEN = os.environ.get("HALDIR_BOOTSTRAP_TOKEN", "")


def setup() -> tuple[str, dict, str]:
    """Create API key, session, and return (api_key, headers, session_id)."""
    headers = {"Content-Type": "application/json"}

    # Create API key
    resp = httpx.post(
        f"{BASE_URL}/v1/keys",
        headers=headers,
        json={"name": "approval-demo", "bootstrap_token": BOOTSTRAP_TOKEN},
    )
    if resp.status_code != 201:
        print(f"[-] Failed to create API key: {resp.text}")
        sys.exit(1)
    api_key = resp.json()["key"]

    auth = {**headers, "Authorization": f"Bearer {api_key}"}

    # Create session
    resp = httpx.post(
        f"{BASE_URL}/v1/sessions",
        headers=auth,
        json={
            "agent_id": "finance-bot",
            "scopes": ["read", "write", "execute"],
            "ttl": 3600,
            "spend_limit": 500.00,
        },
    )
    if resp.status_code != 201:
        print(f"[-] Failed to create session: {resp.text}")
        sys.exit(1)

    session_id = resp.json()["session_id"]
    return api_key, auth, session_id


def main():
    print("[*] Haldir Human-in-the-Loop Demo")
    print(f"[*] Target: {BASE_URL}\n")

    api_key, headers, session_id = setup()
    print(f"[+] API key: {api_key[:12]}...")
    print(f"[+] Session: {session_id}")
    print(f"[+] Agent: finance-bot (scopes: read, write, execute)")

    # ── Step 1: Add approval rules ──
    # Rules define which actions need human approval before proceeding.
    print("\n[*] Step 1: Adding approval rules...")

    # Rule 1: Any spend over $100 needs approval
    resp = httpx.post(
        f"{BASE_URL}/v1/approvals/rules",
        headers=headers,
        json={"type": "spend_over", "threshold": 100.00},
    )
    if resp.status_code == 201:
        print("[+] Rule added: spend_over($100) requires approval")
    else:
        print(f"[-] Failed to add rule: {resp.text}")

    # Rule 2: Specific tools always need approval
    resp = httpx.post(
        f"{BASE_URL}/v1/approvals/rules",
        headers=headers,
        json={"type": "tool_blocked", "tools": ["stripe", "bank_transfer"]},
    )
    if resp.status_code == 201:
        print("[+] Rule added: tool_blocked(stripe, bank_transfer) requires approval")
    else:
        print(f"[-] Failed to add rule: {resp.text}")

    # Rule 3: Destructive actions need approval
    resp = httpx.post(
        f"{BASE_URL}/v1/approvals/rules",
        headers=headers,
        json={"type": "destructive"},
    )
    if resp.status_code == 201:
        print("[+] Rule added: destructive actions (delete, write, send) require approval")
    else:
        print(f"[-] Failed to add rule: {resp.text}")

    # ── Step 2: Agent requests approval ──
    # The agent wants to make a $250 payment. This exceeds the $100 threshold,
    # so it creates an approval request and waits.
    print("\n[*] Step 2: Agent requests approval for a $250 payment...")
    print("    (Agent) I need to pay $250 for premium API access.")
    print("    (Agent) This exceeds the $100 threshold. Requesting approval...")

    resp = httpx.post(
        f"{BASE_URL}/v1/approvals/request",
        headers=headers,
        json={
            "session_id": session_id,
            "tool": "stripe",
            "action": "charge",
            "amount": 250.00,
            "reason": "Purchase premium API access for data enrichment pipeline",
            "details": {
                "vendor": "Clearbit",
                "plan": "Business",
                "billing_cycle": "annual",
            },
            "ttl": 3600,   # Request expires in 1 hour
        },
    )
    if resp.status_code != 201:
        print(f"[-] Failed to request approval: {resp.text}")
        sys.exit(1)

    request_id = resp.json()["request_id"]
    print(f"[+] Approval request created: {request_id}")
    print(f"    Status: {resp.json()['status']}")

    # ── Step 3: Agent polls for approval status ──
    # In production, the agent would poll periodically or listen for a webhook.
    print("\n[*] Step 3: Agent polls for approval status...")

    resp = httpx.get(
        f"{BASE_URL}/v1/approvals/{request_id}",
        headers=headers,
    )
    if resp.status_code == 200:
        status = resp.json()
        print(f"    Status: {status['status']}")
        print(f"    Tool: {status['tool']}")
        print(f"    Action: {status['action']}")
        print(f"    Amount: ${status['amount']:.2f}")
        print(f"    Reason: {status['reason']}")
    else:
        print(f"[-] Failed to check approval: {resp.text}")

    # ── Step 4: Check pending approvals (human dashboard view) ──
    print("\n[*] Step 4: Human checks pending approvals...")
    print("    (Human) Let me see what the agents need...")

    resp = httpx.get(
        f"{BASE_URL}/v1/approvals/pending",
        headers=headers,
        params={"agent_id": "finance-bot"},
    )
    if resp.status_code == 200:
        pending = resp.json()
        print(f"[+] Pending approvals: {pending['count']}")
        for req in pending["requests"]:
            print(f"    - [{req['request_id'][:16]}...] {req['agent_id']}: "
                  f"{req['tool']}/{req['action']} (${req['amount']:.2f})")
            print(f"      Reason: {req['reason']}")
    else:
        print(f"[-] Failed to get pending approvals: {resp.text}")

    # ── Step 5: Human approves the request ──
    print("\n[*] Step 5: Human approves the request...")
    print("    (Human) Clearbit Business plan looks right. Approved.")

    resp = httpx.post(
        f"{BASE_URL}/v1/approvals/{request_id}/approve",
        headers=headers,
        json={
            "decided_by": "sterling",
            "note": "Approved — Clearbit is on our vendor list",
        },
    )
    if resp.status_code == 200:
        print(f"[+] Request approved by: sterling")
    else:
        print(f"[-] Failed to approve: {resp.text}")

    # ── Step 6: Agent polls again and sees approval ──
    print("\n[*] Step 6: Agent polls again...")

    resp = httpx.get(
        f"{BASE_URL}/v1/approvals/{request_id}",
        headers=headers,
    )
    if resp.status_code == 200:
        status = resp.json()
        print(f"    Status: {status['status']}")
        print(f"    Decided by: {status['decided_by']}")
        print(f"    Note: {status['decision_note']}")

        if status["status"] == "approved":
            print("\n    (Agent) Approval received. Proceeding with payment...")
            # Now the agent would call the actual payment endpoint
            resp = httpx.post(
                f"{BASE_URL}/v1/payments/authorize",
                headers=headers,
                json={
                    "session_id": session_id,
                    "amount": 250.00,
                    "currency": "USD",
                    "description": "Clearbit Business — annual subscription",
                },
            )
            if resp.status_code == 200 and resp.json().get("authorized"):
                print(f"    [+] Payment authorized: ${resp.json()['amount']}")
                print(f"    [+] Remaining budget: ${resp.json()['remaining_budget']:.2f}")
            else:
                print(f"    [-] Payment failed: {resp.text}")
        elif status["status"] == "denied":
            print("    (Agent) Request denied. Aborting payment.")
        elif status["status"] == "expired":
            print("    (Agent) Request expired. Need to re-request.")
    else:
        print(f"[-] Failed to check approval: {resp.text}")

    # ── Bonus: Demonstrate a denial ──
    print("\n" + "-" * 50)
    print("[*] Bonus: Demonstrating a denial...\n")

    # Agent requests approval for something suspicious
    print("    (Agent) I want to transfer $10,000 to an external account...")
    resp = httpx.post(
        f"{BASE_URL}/v1/approvals/request",
        headers=headers,
        json={
            "session_id": session_id,
            "tool": "bank_transfer",
            "action": "send",
            "amount": 10000.00,
            "reason": "Transfer funds to vendor for hardware purchase",
            "details": {"recipient": "unknown-vendor@offshore.biz", "bank": "Cayman National"},
        },
    )
    if resp.status_code == 201:
        deny_id = resp.json()["request_id"]
        print(f"[+] Approval request: {deny_id}")

        # Human denies it
        print("\n    (Human) This looks suspicious. Denying.")
        resp = httpx.post(
            f"{BASE_URL}/v1/approvals/{deny_id}/deny",
            headers=headers,
            json={
                "decided_by": "sterling",
                "note": "Suspicious recipient. Investigate agent behavior.",
            },
        )
        if resp.status_code == 200:
            print(f"[+] Request denied")

        # Agent sees the denial
        resp = httpx.get(f"{BASE_URL}/v1/approvals/{deny_id}", headers=headers)
        if resp.status_code == 200:
            status = resp.json()
            print(f"\n    (Agent) Status: {status['status']}")
            print(f"    (Agent) Note from reviewer: {status['decision_note']}")
            print("    (Agent) Aborting transfer.")

    # ── Cleanup ──
    httpx.delete(f"{BASE_URL}/v1/sessions/{session_id}", headers=headers)
    print(f"\n[+] Session revoked. Approval demo complete.")


if __name__ == "__main__":
    main()
