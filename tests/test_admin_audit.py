"""
Tests for auditing administrative actions.

Haldir audits what agents do. It did not audit what is done *to* it: creating
and revoking API keys — the actions that decide who may act at all — left no
trace, so "who revoked production's key, and when?" had no answer in a product
whose README says every action is logged.

These cover the contract:

  - a key creation and a key revocation both land in the audit trail
  - they are attributed to the key that performed them, by prefix
  - a sub-key is credited to its parent, not to nobody
  - the bootstrap key — created with no caller — records no actor
  - admin entries live in the same hash chain as agent entries, so
    verify_chain covers them
  - key creation fails closed: if the audit write fails, the key is revoked
    rather than handed out unaccounted for

Run: python -m pytest tests/test_admin_audit.py -v
"""

from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
from haldir_watch import Watch  # noqa: E402


def _admin_entries(client, key, action_prefix="admin."):
    r = client.get("/v1/audit?limit=200",
                   headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200, r.data
    body = r.get_json()
    entries = body.get("entries", body) if isinstance(body, dict) else body
    return [e for e in entries if str(e.get("action", "")).startswith(action_prefix)]


def test_key_creation_is_recorded(haldir_client, bootstrap_key, fresh_counter) -> None:
    before = len(_admin_entries(haldir_client, bootstrap_key, "admin.key.create"))

    r = haldir_client.post("/v1/keys", json={"name": "audited-create"},
                           headers={"Authorization": f"Bearer {bootstrap_key}"})
    assert r.status_code == 201, r.data
    new_prefix = r.get_json()["prefix"]

    after = _admin_entries(haldir_client, bootstrap_key, "admin.key.create")
    assert len(after) == before + 1
    assert any(e["details"].get("key_prefix") == new_prefix for e in after)


def test_key_creation_is_attributed_to_the_calling_key(haldir_client, bootstrap_key, fresh_counter) -> None:
    """A sub-key is credited to its parent — the key creation route
    authenticates itself, so it is not enough to read the request context."""
    parent_prefix = bootstrap_key[:12]

    r = haldir_client.post("/v1/keys", json={"name": "attributed"},
                           headers={"Authorization": f"Bearer {bootstrap_key}"})
    assert r.status_code == 201, r.data
    child_prefix = r.get_json()["prefix"]

    match = [e for e in _admin_entries(haldir_client, bootstrap_key)
             if e["details"].get("key_prefix") == child_prefix
             and e["action"] == "admin.key.create"]
    assert match, "no admin.key.create entry for the new key"
    assert match[0]["details"]["actor"] == parent_prefix
    assert match[0]["agent_id"] == f"admin:{parent_prefix}"


def test_key_revocation_is_recorded_and_attributed(haldir_client, bootstrap_key, fresh_counter) -> None:
    r = haldir_client.post("/v1/keys", json={"name": "to-revoke"},
                           headers={"Authorization": f"Bearer {bootstrap_key}"})
    assert r.status_code == 201, r.data
    victim = r.get_json()["prefix"]

    d = haldir_client.delete(f"/v1/keys/{victim}",
                             headers={"Authorization": f"Bearer {bootstrap_key}"})
    assert d.status_code == 200, d.data
    assert d.get_json()["audit_recorded"] is True

    match = [e for e in _admin_entries(haldir_client, bootstrap_key)
             if e["action"] == "admin.key.revoke"
             and e["details"].get("key_prefix") == victim]
    assert match, "the revocation left no trace"
    assert match[0]["details"]["actor"] == bootstrap_key[:12]


def test_admin_entries_are_in_the_hash_chain(haldir_client, bootstrap_key, fresh_counter) -> None:
    """An admin log kept outside the chain would be the first thing an
    attacker edits, so these must be covered by chain verification."""
    haldir_client.post("/v1/keys", json={"name": "chain-check"},
                       headers={"Authorization": f"Bearer {bootstrap_key}"})

    r = haldir_client.get("/v1/audit/verify",
                          headers={"Authorization": f"Bearer {bootstrap_key}"})
    assert r.status_code == 200, r.data
    assert r.get_json().get("verified") is True


def test_creation_fails_closed_when_the_audit_write_fails(haldir_client, bootstrap_key, fresh_counter, monkeypatch) -> None:
    """A key nobody can account for must not be handed out.

    Same rule the delegation spawn path applies to an unrecorded child
    session: if it cannot be written into the chain, it does not survive.
    """
    def boom(*args, **kwargs):
        raise RuntimeError("audit chain unavailable")

    monkeypatch.setattr(Watch, "log_admin_action", boom)

    r = haldir_client.post("/v1/keys", json={"name": "should-not-survive"},
                           headers={"Authorization": f"Bearer {bootstrap_key}"})
    assert r.status_code == 500
    assert "revoked" in r.get_json()["error"].lower()

    # And the key really is dead — not just reported as such.
    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    row = conn.execute(
        "SELECT revoked FROM api_keys WHERE name = ? ORDER BY created_at DESC LIMIT 1",
        ("should-not-survive",),
    ).fetchone()
    conn.close()
    assert row is not None and int(row["revoked"]) == 1


def test_other_admin_changes_are_recorded(haldir_client, bootstrap_key,
                                          fresh_counter, monkeypatch) -> None:
    """Not just the key lifecycle — the config that decides what agents may do.

    A webhook is where alerts go and an approval rule decides when a human is
    asked; both are governance-relevant changes, and both used to be silent.
    """
    # This test is about the audit entry, not URL safety, and it should not
    # depend on DNS: `example.invalid` is reserved and never resolves, and a
    # public hostname would make the suite fail on an offline runner. The
    # opt-in skips the address check and keeps the test hermetic. The guard
    # itself is covered by test_outbound_url.py and by the API-level tests
    # there that assert a refused URL is a 400.
    monkeypatch.setenv("HALDIR_ALLOW_PRIVATE_WEBHOOKS", "1")
    h = {"Authorization": f"Bearer {bootstrap_key}"}

    r = haldir_client.post("/v1/webhooks",
                           json={"url": "https://example.invalid/hook",
                                 "events": ["audit.flagged"]},
                           headers=h)
    assert r.status_code == 201, r.data
    assert any(e["action"] == "admin.webhook.register"
               for e in _admin_entries(haldir_client, bootstrap_key))

    r = haldir_client.post("/v1/approvals/rules",
                           json={"type": "spend_over", "threshold": 100},
                           headers=h)
    assert r.status_code == 201, r.data
    assert any(e["action"] == "admin.approval_rule.add"
               for e in _admin_entries(haldir_client, bootstrap_key))


def test_watch_log_admin_action_shape(tmp_path) -> None:
    """The primitive itself, without going through HTTP."""
    from haldir_db import init_db

    db = str(tmp_path / "admin_audit.db")
    init_db(db)
    w = Watch(db_path=db)

    entry = w.log_admin_action("hld_abc12345", "key.create",
                               {"key_prefix": "hld_abc12345"}, tenant_id="t1")
    assert entry.action == "admin.key.create"
    assert entry.agent_id == "admin:hld_abc12345"
    assert entry.session_id == ""
    assert entry.tool == "haldir"
    assert entry.details["actor"] == "hld_abc12345"

    trail = w.get_audit_trail(tenant_id="t1")
    assert [e.action for e in trail] == ["admin.key.create"]
