"""
Haldir API test — exercises every endpoint.
"""

import os
import sys
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

os.environ["HALDIR_DB_PATH"] = "/tmp/haldir_api_test.db"

# Clean start
if os.path.exists("/tmp/haldir_api_test.db"):
    os.remove("/tmp/haldir_api_test.db")

from api import app

client = app.test_client()


def test_full_api():
    print("[*] Haldir API test\n")

    # 1. Health check
    r = client.get("/healthz")
    assert r.status_code == 200
    print("[+] Health check OK")

    # 2. Root endpoint
    r = client.get("/")
    assert r.status_code == 200
    assert "haldir" in r.json["service"]
    print("[+] Root endpoint OK")

    # 3. Create first API key (no auth needed for first key)
    r = client.post("/v1/keys", json={"name": "test-key", "tier": "pro"})
    assert r.status_code == 201
    api_key = r.json["key"]
    assert api_key.startswith("hld_")
    print(f"[+] API key created: {api_key[:12]}...")

    headers = {"Authorization": f"Bearer {api_key}"}

    # 4. Create session
    r = client.post("/v1/sessions", json={
        "agent_id": "test-bot",
        "scopes": ["read", "browse", "spend"],
        "ttl": 3600,
        "spend_limit": 100.0,
    }, headers=headers)
    assert r.status_code == 201
    session_id = r.json["session_id"]
    print(f"[+] Session created: {session_id[:20]}...")

    # 5. Get session
    r = client.get(f"/v1/sessions/{session_id}", headers=headers)
    assert r.status_code == 200
    assert r.json["spend_limit"] == 100.0
    print(f"[+] Session retrieved: budget=${r.json['spend_limit']}")

    # 6. Check permission
    r = client.post(f"/v1/sessions/{session_id}/check", json={"scope": "read"}, headers=headers)
    assert r.json["allowed"] == True
    r = client.post(f"/v1/sessions/{session_id}/check", json={"scope": "delete"}, headers=headers)
    assert r.json["allowed"] == False
    print("[+] Permission checks passed")

    # 7. Store secret
    r = client.post("/v1/secrets", json={
        "name": "stripe_key",
        "value": "sk_test_abc123",
        "scope_required": "read",
    }, headers=headers)
    assert r.status_code == 201
    print("[+] Secret stored")

    # 8. Get secret (with session)
    r = client.get(f"/v1/secrets/stripe_key",
                   headers={**headers, "X-Session-ID": session_id})
    assert r.status_code == 200
    assert r.json["value"] == "sk_test_abc123"
    print(f"[+] Secret retrieved: {r.json['value'][:10]}...")

    # 9. List secrets
    r = client.get("/v1/secrets", headers=headers)
    assert "stripe_key" in r.json["secrets"]
    print(f"[+] Secrets listed: {r.json['secrets']}")

    # 10. Authorize payment
    r = client.post("/v1/payments/authorize", json={
        "session_id": session_id,
        "amount": 29.99,
        "description": "Test payment",
    }, headers=headers)
    assert r.status_code == 200
    assert r.json["authorized"] == True
    print(f"[+] Payment authorized: ${r.json['amount']} — remaining: ${r.json['remaining_budget']}")

    # 11. Overspend
    r = client.post("/v1/payments/authorize", json={
        "session_id": session_id,
        "amount": 80.00,
    }, headers=headers)
    assert r.status_code == 403
    assert r.json["authorized"] == False
    print(f"[+] Overspend blocked: {r.json['reason']}")

    # 12. Log action
    r = client.post("/v1/audit", json={
        "session_id": session_id,
        "tool": "stripe",
        "action": "charge",
        "cost_usd": 29.99,
    }, headers=headers)
    assert r.status_code == 201
    assert r.json["logged"] == True
    print(f"[+] Action logged: {r.json['entry_id']}")

    # 13. Query audit trail
    r = client.get(f"/v1/audit?agent_id=test-bot", headers=headers)
    assert r.json["count"] == 1
    print(f"[+] Audit trail: {r.json['count']} entries")

    # 14. Get spend
    r = client.get(f"/v1/audit/spend?agent_id=test-bot", headers=headers)
    assert r.json["total_usd"] == 29.99
    print(f"[+] Spend: ${r.json['total_usd']} — by tool: {r.json['by_tool']}")

    # 15. Revoke session
    r = client.delete(f"/v1/sessions/{session_id}", headers=headers)
    assert r.json["revoked"] == True
    print("[+] Session revoked")

    # 16. Verify revoked
    r = client.get(f"/v1/sessions/{session_id}", headers=headers)
    assert r.status_code == 404
    print("[+] Revoked session returns 404")

    # 17. Delete secret
    r = client.delete("/v1/secrets/stripe_key", headers=headers)
    assert r.json["deleted"] == True
    print("[+] Secret deleted")

    # 18. Unauthorized request
    r = client.get("/v1/secrets", headers={"Authorization": "Bearer bad_key"})
    assert r.status_code == 401
    print("[+] Bad key rejected")

    # Cleanup
    os.remove("/tmp/haldir_api_test.db")
    print(f"\n[+] All API tests passed!")


if __name__ == "__main__":
    test_full_api()
