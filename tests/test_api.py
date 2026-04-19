"""
Haldir API end-to-end smoke test — exercises every primitive endpoint
against conftest's shared bootstrap key.

Historically this module bootstrapped its own key via the no-auth
/v1/keys path, which is only legal when api_keys is empty. In the
wider test suite, conftest.py creates a session-scoped bootstrap_key
before any module-level imports run, so the table isn't empty by the
time this module's first test fires. The clean fix is to piggyback
on conftest's bootstrap_key instead of racing it.
"""

import os
import sys
import uuid
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Keep the env-var + tmp-DB dance for back-compat when this module is
# run directly (`python tests/test_api.py`). Under pytest with the rest
# of the suite, api.py has already been imported from conftest's code
# path and api.DB_PATH is frozen; our override here is a no-op.
os.environ.setdefault("HALDIR_DB_PATH", "/tmp/haldir_api_test.db")

from api import app

client = app.test_client()


@pytest.fixture(autouse=True)
def _lift_agent_cap(monkeypatch):
    """Lift the free-tier agent cap so this smoke test can mint a
    session even after the rest of the suite has accumulated agents
    on the shared bootstrap tenant. Same pattern as test_admin,
    test_compliance_score, test_audit_tree."""
    import copy
    import api
    patched = copy.deepcopy(api.TIER_LIMITS)
    patched["free"]["agents"] = 999
    monkeypatch.setattr(api, "TIER_LIMITS", patched)


def test_full_api(bootstrap_key):
    print("[*] Haldir API test\n")

    # Unique agent_id so the audit-trail count assertion below isn't
    # polluted by other tests that share the same tenant.
    agent_id = f"test-bot-{uuid.uuid4().hex[:8]}"

    # 1. Health check
    r = client.get("/healthz")
    assert r.status_code == 200
    print("[+] Health check OK")

    # 2. Root endpoint (serves landing page HTML)
    r = client.get("/")
    assert r.status_code == 200
    print("[+] Root endpoint OK")

    # 2b. API index
    r = client.get("/v1")
    assert r.status_code == 200
    assert "haldir" in r.json["service"]
    print("[+] API index OK")

    # 3. Use conftest's bootstrap key; the "first key" bootstrap path
    # is covered separately in test_keys_admin.py.
    api_key = bootstrap_key
    print(f"[+] Using bootstrap key: {api_key[:12]}...")

    headers = {"Authorization": f"Bearer {api_key}"}

    # 4. Create session
    r = client.post("/v1/sessions", json={
        "agent_id": agent_id,
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

    # Unique secret name so repeated runs don't collide.
    secret_name = f"stripe_key_{uuid.uuid4().hex[:8]}"

    # 7. Store secret
    r = client.post("/v1/secrets", json={
        "name": secret_name,
        "value": "sk_test_abc123",
        "scope_required": "read",
    }, headers=headers)
    assert r.status_code == 201
    print("[+] Secret stored")

    # 8. Get secret (with session)
    r = client.get(f"/v1/secrets/{secret_name}",
                   headers={**headers, "X-Session-ID": session_id})
    assert r.status_code == 200
    assert r.json["value"] == "sk_test_abc123"
    print(f"[+] Secret retrieved: {r.json['value'][:10]}...")

    # 9. List secrets
    r = client.get("/v1/secrets", headers=headers)
    assert secret_name in r.json["secrets"]
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
    r = client.get(f"/v1/audit?agent_id={agent_id}", headers=headers)
    assert r.json["count"] == 1
    print(f"[+] Audit trail: {r.json['count']} entries")

    # 14. Get spend
    r = client.get(f"/v1/audit/spend?agent_id={agent_id}", headers=headers)
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
    r = client.delete(f"/v1/secrets/{secret_name}", headers=headers)
    assert r.json["deleted"] == True
    print("[+] Secret deleted")

    # 18. Unauthorized request
    r = client.get("/v1/secrets", headers={"Authorization": "Bearer bad_key"})
    assert r.status_code == 401
    print("[+] Bad key rejected")

    # No destructive DB cleanup here: api.DB_PATH is frozen at import
    # time and is shared with every other test module in this run.
    # Removing the file stranded the next suite with "no such table".
    print(f"\n[+] All API tests passed!")


if __name__ == "__main__":
    print("Run this module under pytest: `pytest tests/test_api.py -v`.")
    print("It needs the session-scoped bootstrap_key fixture from conftest.")
