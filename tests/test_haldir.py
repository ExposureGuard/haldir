"""
Haldir integration test — runs through the full Gate → Vault → Watch pipeline.
"""

import sys
sys.path.insert(0, '..')

from haldir_gate import Gate, Permission
from haldir_vault import Vault
from haldir_watch import Watch


def test_full_pipeline():
    print("[*] Haldir integration test\n")

    # 1. Gate: create agent and session
    gate = Gate()
    gate.register_agent("research-bot", default_scopes=["read", "browse", "spend"], max_spend=100.0)
    session = gate.create_session("research-bot", scopes=["read", "browse", "spend:50"], ttl=3600)
    print(f"[+] Session created: {session.session_id}")
    print(f"    Agent: {session.agent_id}")
    print(f"    Scopes: {session.scopes}")
    print(f"    Budget: ${session.spend_limit:.2f}")

    # 2. Gate: check permissions
    assert gate.check_permission(session.session_id, "read") == True
    assert gate.check_permission(session.session_id, "browse") == True
    assert gate.check_permission(session.session_id, "delete") == False
    print("[+] Permission checks passed")

    # 3. Vault: store and retrieve secrets
    vault = Vault()
    vault.store_secret("stripe_key", "sk_test_abc123", scope_required="read")
    vault.store_secret("admin_password", "hunter2", scope_required="admin")

    stripe_key = vault.get_secret("stripe_key", session=session)
    assert stripe_key == "sk_test_abc123"
    print(f"[+] Secret retrieved: stripe_key = {stripe_key[:10]}...")

    # Should fail — session doesn't have admin scope
    try:
        vault.get_secret("admin_password", session=session)
        assert False, "Should have raised PermissionError"
    except PermissionError:
        print("[+] Admin secret correctly blocked")

    # 4. Vault: authorize payment
    auth = vault.authorize_payment(session, 29.99, description="API subscription")
    assert auth["authorized"] == True
    print(f"[+] Payment authorized: ${auth['amount']:.2f} — remaining: ${auth['remaining_budget']:.2f}")

    # Try to overspend
    auth2 = vault.authorize_payment(session, 25.00, description="Another charge")
    assert auth2["authorized"] == False
    print(f"[+] Overspend correctly blocked: {auth2['reason']}")

    # 5. Watch: log actions
    watch = Watch()
    watch.add_anomaly_rule("spend_per_action", 50.0, "Single action over $50")
    watch.add_anomaly_rule("actions_per_minute", 100, "Too many actions per minute")

    e1 = watch.log_action(session, tool="stripe", action="charge", cost_usd=29.99)
    e2 = watch.log_action(session, tool="exposureguard", action="scan_domain", cost_usd=0.0,
                          details={"domain": "example.com"})
    print(f"[+] Actions logged: {e1.entry_id}, {e2.entry_id}")

    # 6. Watch: query audit trail
    trail = watch.get_audit_trail(agent_id="research-bot")
    print(f"[+] Audit trail: {len(trail)} entries")

    spend = watch.get_spend(agent_id="research-bot")
    print(f"[+] Total spend: ${spend['total_usd']:.2f}")
    print(f"    By tool: {spend['by_tool']}")

    # 7. Gate: revoke session
    gate.revoke_session(session.session_id)
    assert gate.check_permission(session.session_id, "read") == False
    print("[+] Session revoked — all permissions denied")

    print("\n[+] All tests passed!")


if __name__ == "__main__":
    test_full_pipeline()
