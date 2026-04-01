"""
Haldir persistent storage test — full pipeline with SQLite.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from haldir_db import init_db
from haldir_gate import Gate
from haldir_vault import Vault
from haldir_watch import Watch

DB_PATH = "/tmp/haldir_test.db"


def test_persistent_pipeline():
    # Clean start
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    print("[*] Haldir persistent storage test\n")

    # Init DB
    init_db(DB_PATH)
    print("[+] Database initialized")

    # Create components with shared DB
    gate = Gate(db_path=DB_PATH)
    vault = Vault(db_path=DB_PATH)
    watch = Watch(db_path=DB_PATH)

    # Register agent and create session
    gate.register_agent("crawler-agent", default_scopes=["read", "browse", "spend"], max_spend=200.0)
    session = gate.create_session("crawler-agent", scopes=["read", "browse", "spend:100"], ttl=7200)
    print(f"[+] Session: {session.session_id}")
    print(f"    Budget: ${session.spend_limit:.2f}")

    # Store secrets
    vault.store_secret("openai_key", "sk-abc123xyz", scope_required="read")
    vault.store_secret("db_password", "supersecret", scope_required="admin")
    print("[+] Secrets stored")

    # Retrieve secret
    key = vault.get_secret("openai_key", session=session)
    assert key == "sk-abc123xyz"
    print(f"[+] Secret retrieved: {key[:8]}...")

    # Block unauthorized access
    try:
        vault.get_secret("db_password", session=session)
        assert False
    except PermissionError:
        print("[+] Admin secret blocked correctly")

    # Authorize payments
    auth1 = vault.authorize_payment(session, 25.00, description="API call")
    assert auth1["authorized"]
    print(f"[+] Payment 1: ${auth1['amount']:.2f} — remaining: ${auth1['remaining_budget']:.2f}")

    auth2 = vault.authorize_payment(session, 50.00, description="Data purchase")
    assert auth2["authorized"]
    print(f"[+] Payment 2: ${auth2['amount']:.2f} — remaining: ${auth2['remaining_budget']:.2f}")

    auth3 = vault.authorize_payment(session, 30.00, description="Should fail")
    assert not auth3["authorized"]
    print(f"[+] Payment 3 blocked: {auth3['reason']}")

    # Log actions
    watch.add_anomaly_rule("spend_per_action", 75.0, "High-cost action")
    e1 = watch.log_action(session, tool="openai", action="gpt4_call", cost_usd=0.03)
    e2 = watch.log_action(session, tool="stripe", action="charge", cost_usd=25.00)
    e3 = watch.log_action(session, tool="exposureguard", action="scan_domain",
                          details={"domain": "example.com"})
    print(f"[+] Logged {3} actions")

    # Query audit trail
    trail = watch.get_audit_trail(agent_id="crawler-agent")
    assert len(trail) == 3
    print(f"[+] Audit trail: {len(trail)} entries")

    # Spend report
    spend = watch.get_spend(agent_id="crawler-agent")
    print(f"[+] Total spend: ${spend['total_usd']:.2f}")
    print(f"    By tool: {spend['by_tool']}")

    # Verify persistence — create new instances pointing to same DB
    gate2 = Gate(db_path=DB_PATH)
    session2 = gate2.get_session(session.session_id)
    assert session2 is not None
    assert session2.spent == 75.0
    print(f"[+] Session persisted: spent=${session2.spent:.2f}")

    watch2 = Watch(db_path=DB_PATH)
    trail2 = watch2.get_audit_trail(agent_id="crawler-agent")
    assert len(trail2) == 3
    print(f"[+] Audit log persisted: {len(trail2)} entries")

    vault2 = Vault(encryption_key=vault.encryption_key, db_path=DB_PATH)
    secrets = vault2.list_secrets()
    assert "openai_key" in secrets
    print(f"[+] Secrets persisted: {secrets}")

    # Revoke and verify
    gate.revoke_session(session.session_id)
    session3 = gate2.get_session(session.session_id)
    assert session3 is None
    print("[+] Session revoked and verified in DB")

    # Cleanup
    os.remove(DB_PATH)
    print(f"\n[+] All persistent storage tests passed!")


if __name__ == "__main__":
    test_persistent_pipeline()
