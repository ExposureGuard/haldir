"""
Tests for the agent delegation hierarchy.

A session may name a parent, forming a bounded chain: an orchestrator agent
spawns subagents, and the whole run is addressable as one tree. This file
covers the invariants that make that safe to expose:

  Gate
    - depth is counted from the root; roots are depth 0
    - a parent must exist, in the caller's own tenant
    - nesting is bounded by MAX_DELEGATION_DEPTH, checked before anything
      is minted so a refused spawn leaves no partial state
    - a stored cycle cannot make any walk hang

  HTTP
    - POST /v1/sessions accepts parent_session_id and reports the depth
    - an unknown parent is a 400, not a 500 or an orphan session
    - GET /v1/sessions?roots_only=true returns only chain tops
    - GET /v1/sessions/<id>/descendants returns the nested subtree with
      cost rolled up from the leaves
    - DELETE /v1/sessions/<id>?cascade=true revokes the subtree
    - a subagent does not consume a tier agent slot (roots only) — otherwise
      one orchestrator could never build a tree on a small tier

Run: python -m pytest tests/test_delegation.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
from haldir_gate import DelegationError, Gate, MAX_DELEGATION_DEPTH  # noqa: E402


# ── Gate ─────────────────────────────────────────────────────────────────

@pytest.fixture
def gate(tmp_path):
    """A Gate over its own throwaway database.

    Delegation is a persisted property (the parent link lives on the sessions
    row), so these run against a real SQLite file rather than the in-memory
    fallback — the fallback would not exercise the column at all.
    """
    from haldir_db import init_db

    db = str(tmp_path / "delegation.db")
    init_db(db)
    g = Gate(db_path=db)
    # Distinct agents so each level is attributable in the tree.
    for name in ("orchestrator", "researcher", "summariser"):
        g.register_agent(name, default_scopes=["read"], tenant_id="t1")
    return g


def test_root_session_is_depth_zero(gate) -> None:
    root = gate.create_session("orchestrator", tenant_id="t1")
    assert root.parent_session_id == ""
    assert gate.delegation_depth(root.session_id, tenant_id="t1") == 0


def test_child_depth_follows_chain(gate) -> None:
    root = gate.create_session("orchestrator", tenant_id="t1")
    child = gate.create_session("researcher", tenant_id="t1",
                                parent_session_id=root.session_id)
    grandchild = gate.create_session("summariser", tenant_id="t1",
                                     parent_session_id=child.session_id)

    assert child.parent_session_id == root.session_id
    assert gate.delegation_depth(child.session_id, tenant_id="t1") == 1
    assert gate.delegation_depth(grandchild.session_id, tenant_id="t1") == 2


def test_unknown_parent_is_rejected(gate) -> None:
    with pytest.raises(DelegationError):
        gate.create_session("researcher", tenant_id="t1",
                            parent_session_id="ses_does_not_exist")


def test_parent_in_another_tenant_is_rejected(gate) -> None:
    """A tenant must not be able to graft onto someone else's chain."""
    gate.register_agent("researcher", default_scopes=["read"], tenant_id="t2")
    other = gate.create_session("researcher", tenant_id="t2")

    with pytest.raises(DelegationError):
        gate.create_session("researcher", tenant_id="t1",
                            parent_session_id=other.session_id)


def test_depth_cap_is_enforced_at_the_boundary(gate) -> None:
    """MAX_DELEGATION_DEPTH is inclusive; one past it is refused."""
    gate.register_agent("deep", default_scopes=["read"], tenant_id="t1")

    # A root at depth 0, then MAX_DELEGATION_DEPTH children put the deepest
    # session at exactly the ceiling. The cap is `depth > MAX`, so this last
    # one must still be allowed.
    prev = gate.create_session("deep", tenant_id="t1").session_id
    for _ in range(MAX_DELEGATION_DEPTH):
        prev = gate.create_session("deep", tenant_id="t1",
                                   parent_session_id=prev).session_id
    assert gate.delegation_depth(prev, tenant_id="t1") == MAX_DELEGATION_DEPTH

    with pytest.raises(DelegationError):
        gate.create_session("deep", tenant_id="t1", parent_session_id=prev)


def test_refused_spawn_leaves_no_session_behind(gate) -> None:
    """Validation happens before minting, so a rejected spawn is not partial."""
    before = len(gate.list_sessions(tenant_id="t1"))
    with pytest.raises(DelegationError):
        gate.create_session("researcher", tenant_id="t1",
                            parent_session_id="ses_missing")
    assert len(gate.list_sessions(tenant_id="t1")) == before


def test_children_and_descendants(gate) -> None:
    root = gate.create_session("orchestrator", tenant_id="t1")
    a = gate.create_session("researcher", tenant_id="t1",
                            parent_session_id=root.session_id)
    b = gate.create_session("summariser", tenant_id="t1",
                            parent_session_id=root.session_id)
    c = gate.create_session("summariser", tenant_id="t1",
                            parent_session_id=a.session_id)

    child_ids = {s.session_id for s in gate.get_children(root.session_id, tenant_id="t1")}
    assert child_ids == {a.session_id, b.session_id}

    descendant_ids = {s.session_id for s in
                      gate.get_descendants(root.session_id, tenant_id="t1")}
    assert descendant_ids == {a.session_id, b.session_id, c.session_id}

    # A leaf has no descendants, and asks nothing of the DB.
    assert gate.get_descendants(c.session_id, tenant_id="t1") == []


def test_descendants_exclude_revoked_unless_asked(gate) -> None:
    root = gate.create_session("orchestrator", tenant_id="t1")
    child = gate.create_session("researcher", tenant_id="t1",
                                parent_session_id=root.session_id)
    gate.revoke_session(child.session_id, tenant_id="t1")

    assert gate.get_descendants(root.session_id, tenant_id="t1") == []
    kept = gate.get_descendants(root.session_id, tenant_id="t1", include_revoked=True)
    assert [s.session_id for s in kept] == [child.session_id]


def test_a_stored_cycle_cannot_hang_a_walk(gate) -> None:
    """Corrupt data must not turn a read into an infinite loop.

    Nothing in the API can produce this, but the column is plain TEXT and the
    walks are recursive, so the guard is worth pinning down.
    """
    from haldir_db import get_db

    a = gate.create_session("orchestrator", tenant_id="t1")
    b = gate.create_session("researcher", tenant_id="t1",
                            parent_session_id=a.session_id)

    conn = get_db(gate._db_path)
    conn.execute("UPDATE sessions SET parent_session_id = ? WHERE session_id = ?",
                 (b.session_id, a.session_id))   # a → b → a
    conn.commit()
    conn.close()

    # Both must return rather than spin; the exact number is not the contract.
    assert gate.delegation_depth(a.session_id, tenant_id="t1") <= MAX_DELEGATION_DEPTH
    assert len(gate.get_descendants(a.session_id, tenant_id="t1")) <= MAX_DELEGATION_DEPTH


# ── HTTP ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _lift_agent_cap(monkeypatch):
    """Free tier caps agents at 1; these tests build trees."""
    import copy
    patched = copy.deepcopy(api.TIER_LIMITS)
    patched["free"]["agents"] = 999
    monkeypatch.setattr(api, "TIER_LIMITS", patched)


def _mint(client, key, agent_id, parent=None):
    body = {"agent_id": agent_id, "ttl": 86400}
    if parent:
        body["parent_session_id"] = parent
    return client.post("/v1/sessions", json=body,
                       headers={"Authorization": f"Bearer {key}"})


def test_create_session_accepts_a_parent(haldir_client, bootstrap_key, fresh_counter) -> None:
    root = _mint(haldir_client, bootstrap_key, "http-orchestrator")
    assert root.status_code == 201, root.data
    assert root.get_json()["parent_session_id"] == ""
    assert root.get_json()["delegation_depth"] == 0

    child = _mint(haldir_client, bootstrap_key, "http-subagent",
                  parent=root.get_json()["session_id"])
    assert child.status_code == 201, child.data
    assert child.get_json()["parent_session_id"] == root.get_json()["session_id"]
    assert child.get_json()["delegation_depth"] == 1


def test_create_session_rejects_an_unknown_parent(haldir_client, bootstrap_key, fresh_counter) -> None:
    r = _mint(haldir_client, bootstrap_key, "http-orphan", parent="ses_nope")
    assert r.status_code == 400
    assert "parent" in r.get_json()["error"]


def test_roots_only_lists_chain_tops(haldir_client, bootstrap_key, fresh_counter) -> None:
    root = _mint(haldir_client, bootstrap_key, "roots-agent").get_json()["session_id"]
    _mint(haldir_client, bootstrap_key, "roots-sub", parent=root)

    r = haldir_client.get("/v1/sessions?roots_only=true",
                          headers={"Authorization": f"Bearer {bootstrap_key}"})
    assert r.status_code == 200
    ids = [s["session_id"] for s in r.get_json()["sessions"]]
    assert root in ids
    # The child must not appear as its own root.
    for s in r.get_json()["sessions"]:
        assert s["parent_session_id"] == ""


def test_descendants_endpoint_returns_a_nested_tree(haldir_client, bootstrap_key, fresh_counter) -> None:
    root = _mint(haldir_client, bootstrap_key, "tree-root").get_json()["session_id"]
    child = _mint(haldir_client, bootstrap_key, "tree-child", parent=root).get_json()["session_id"]
    _mint(haldir_client, bootstrap_key, "tree-grandchild", parent=child)

    r = haldir_client.get(f"/v1/sessions/{root}/descendants",
                          headers={"Authorization": f"Bearer {bootstrap_key}"})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["descendant_count"] == 2
    assert body["max_delegation_depth"] == MAX_DELEGATION_DEPTH

    node = body["root"]
    assert node["session_id"] == root
    assert len(node["children"]) == 1
    assert node["children"][0]["session_id"] == child
    assert len(node["children"][0]["children"]) == 1

    # Rollup counts the subtree below the root, not the root itself.
    assert node["subtree_sessions"] == 2


def test_cascade_revoke_kills_the_subtree(haldir_client, bootstrap_key, fresh_counter) -> None:
    root = _mint(haldir_client, bootstrap_key, "cascade-root").get_json()["session_id"]
    child = _mint(haldir_client, bootstrap_key, "cascade-child", parent=root).get_json()["session_id"]

    h = {"Authorization": f"Bearer {bootstrap_key}"}
    r = haldir_client.delete(f"/v1/sessions/{root}?cascade=true", headers=h)
    assert r.status_code == 200, r.data
    assert child in r.get_json()["cascade_revoked"]

    # A revoked child must stop resolving.
    assert haldir_client.get(f"/v1/sessions/{child}", headers=h).status_code == 404


def test_plain_revoke_leaves_children_alone(haldir_client, bootstrap_key, fresh_counter) -> None:
    """Cascade is opt-in; deleting a parent without it must not surprise."""
    root = _mint(haldir_client, bootstrap_key, "solo-root").get_json()["session_id"]
    child = _mint(haldir_client, bootstrap_key, "solo-child", parent=root).get_json()["session_id"]

    h = {"Authorization": f"Bearer {bootstrap_key}"}
    assert haldir_client.delete(f"/v1/sessions/{root}", headers=h).status_code == 200
    assert haldir_client.get(f"/v1/sessions/{child}", headers=h).status_code == 200


def test_subagents_do_not_consume_tier_agent_slots(haldir_client, bootstrap_key, fresh_counter, monkeypatch) -> None:
    """The cap counts roots. A tree of twenty must not read as twenty agents.

    Without this, one orchestrator exhausts a small tier simply by delegating.

    The cap is squeezed to zero rather than to a small number: every test in
    this file shares one tenant, so by the time this runs there are already
    roots on it and any fixed limit would be measuring the evidence of the
    tests above rather than this behaviour.
    """
    import copy

    permissive = copy.deepcopy(api.TIER_LIMITS)
    permissive["free"]["agents"] = 999
    monkeypatch.setattr(api, "TIER_LIMITS", permissive)

    root = _mint(haldir_client, bootstrap_key, "cap-root")
    assert root.status_code == 201, root.data
    root_id = root.get_json()["session_id"]

    # No headroom at all: with the cap at zero, any new root is refused...
    tight = copy.deepcopy(api.TIER_LIMITS)
    tight["free"]["agents"] = 0
    monkeypatch.setattr(api, "TIER_LIMITS", tight)

    assert _mint(haldir_client, bootstrap_key, "cap-new-root").status_code == 403

    # ...while children keep being allowed, because they belong to an agent
    # that is already counted.
    for i in range(5):
        r = _mint(haldir_client, bootstrap_key, f"cap-sub-{i}", parent=root_id)
        assert r.status_code == 201, f"child {i} should not count against the cap: {r.data}"


def test_spawn_is_recorded_in_the_audit_chain(haldir_client, bootstrap_key, fresh_counter) -> None:
    """The parent link also lives on the row, but that column is unsigned.

    The delegation record that matters is the one inside the hash chain, so a
    spawn must leave an audit entry behind.
    """
    root = _mint(haldir_client, bootstrap_key, "audit-root").get_json()["session_id"]
    child = _mint(haldir_client, bootstrap_key, "audit-child", parent=root).get_json()["session_id"]

    h = {"Authorization": f"Bearer {bootstrap_key}"}
    r = haldir_client.get("/v1/audit?limit=200", headers=h)
    assert r.status_code == 200
    entries = r.get_json()
    entries = entries.get("entries", entries) if isinstance(entries, dict) else entries

    spawns = [e for e in entries if e.get("action") == "session.spawn"]
    assert spawns, "no session.spawn entry was written"
    match = [e for e in spawns if e.get("session_id") == root]
    assert match, "the spawn was not attributed to the parent session"
    assert match[0]["details"].get("child_session_id") == child
