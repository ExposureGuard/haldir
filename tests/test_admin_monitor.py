"""
Tests for the monitoring console on /admin/overview.

The counts panel above answers "how much has this tenant done". An operator
watching agents needs the other questions: which agent, doing what, right
now, and how do I stop it. This file pins the three sections that answer
them — active sessions with a revoke control, and the recent-activity feed.

Three properties matter more than the rendering:

  1. Tenant isolation. The console is served to whoever holds a key, and a
     session_id is guessable-ish; nothing belonging to another tenant may
     appear, and nothing belonging to another tenant may be revocable.

  2. The revoke control actually revokes, and cascades. A kill switch that
     quietly does nothing is worse than no kill switch, and revoking an
     orchestrator without its subagents leaves live credentials in the hands
     of work nobody is supervising.

  3. Escaping. agent_id, tool and flag_reason are all attacker-influenced:
     an agent picks its own tool names, and a flag reason can quote the
     action that triggered it. A dashboard that renders them raw is stored
     XSS with a customer's audit log as the delivery mechanism.

Run: python -m pytest tests/test_admin_monitor.py -v
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import api  # noqa: E402
import haldir_admin  # noqa: E402


@pytest.fixture(autouse=True)
def _lift_agent_cap(monkeypatch) -> None:
    """Free tier caps agents at 1; these tests mint several."""
    import copy
    patched = copy.deepcopy(api.TIER_LIMITS)
    patched["free"]["agents"] = 999
    monkeypatch.setattr(api, "TIER_LIMITS", patched)


def _tenant(key: str) -> str:
    kh = hashlib.sha256(key.encode()).hexdigest()
    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    row = conn.execute(
        "SELECT tenant_id FROM api_keys WHERE key_hash = ?", (kh,),
    ).fetchone()
    conn.close()
    return row["tenant_id"]


def _page(client, key: str) -> str:
    r = client.get(f"/admin/overview?key={key}")
    assert r.status_code == 200, r.data[:400]
    return r.get_data(as_text=True)


def _foreign_session(agent_id: str = "foreign-agent"):
    """A live session belonging to some other tenant.

    Created through Gate rather than a hand-written INSERT. The direct-SQL
    version collided with itself on a second run (the test database persists
    between runs, so a fixed session_id hit the primary key) and it left
    SQLite holding a write lock against the app's own connections. Going
    through the product's own API avoids both, and is a more honest model of
    how a foreign tenant's session would actually come to exist.
    """
    tenant = f"someone-else-{uuid.uuid4().hex[:8]}"
    return api.gate.create_session(
        agent_id=agent_id, tenant_id=tenant, scopes=["read"],
        spend_limit=100.0, ttl=600,
    ), tenant


@pytest.fixture
def flagged_entry(bootstrap_key):
    """Log one entry that an anomaly rule flags, then remove the rule.

    `flagged` is not a parameter of log_action on purpose: flags are decided
    by rules in the anomaly_rules table and evaluated *before* the entry is
    hashed, so that the flag is covered by the hash. Deciding afterwards
    would let a flag be edited without breaking the chain. A test that wants
    a flagged row therefore has to install a rule and log through a Watch
    that has read it — the rule list is loaded once, in Watch.__init__.

    The rule is removed in teardown because the test database is shared
    across the session: a left-behind rule with threshold 0 would flag every
    later entry in every other test file.
    """
    from haldir_db import get_db
    from haldir_watch import Watch

    tenant = _tenant(bootstrap_key)
    created: list[int] = []
    conn = get_db(api.DB_PATH)
    cur = conn.execute(
        "INSERT INTO anomaly_rules (tenant_id, rule_type, threshold, reason, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (tenant, "spend_per_action", 0.0, "PLACEHOLDER", time.time()),
    )
    created.append(cur.lastrowid)
    conn.commit()
    conn.close()

    def _make(agent_id: str, tool: str, reason: str):
        conn = get_db(api.DB_PATH)
        conn.execute("UPDATE anomaly_rules SET reason = ? WHERE id = ?",
                     (reason, created[-1]))
        conn.commit()
        conn.close()
        # A fresh Watch, so it reads the rule that was just installed.
        w = Watch(db_path=api.DB_PATH)
        sess = api.gate.create_session(agent_id=agent_id, tenant_id=tenant,
                                       scopes=["read"], spend_limit=10.0, ttl=600)
        w.log_action(session=sess, action="tool_call", tool=tool,
                     cost_usd=1.0, tenant_id=tenant)
        return sess

    yield _make

    conn = get_db(api.DB_PATH)
    for rid in created:
        conn.execute("DELETE FROM anomaly_rules WHERE id = ?", (rid,))
    conn.commit()
    conn.close()


# ── The session table ────────────────────────────────────────────────

def test_active_session_is_listed_with_its_agent(haldir_client, bootstrap_key) -> None:
    tenant = _tenant(bootstrap_key)
    sess = api.gate.create_session(
        agent_id="monitor-test-agent", tenant_id=tenant,
        scopes=["read"], spend_limit=25.0, ttl=600,
    )
    try:
        html = _page(haldir_client, bootstrap_key)
        assert "monitor-test-agent" in html, "the session's agent is not on the page"
        assert sess.session_id[:12] in html
        assert "Active agents" in html
    finally:
        api.gate.revoke_session(sess.session_id, tenant_id=tenant)


def test_spend_cap_is_shown_against_the_session(haldir_client, bootstrap_key) -> None:
    """A cap is only useful if the operator can see how close an agent is
    to it before it hits."""
    tenant = _tenant(bootstrap_key)
    sess = api.gate.create_session(
        agent_id="spend-test-agent", tenant_id=tenant,
        scopes=["read"], spend_limit=40.0, ttl=600,
    )
    try:
        html = _page(haldir_client, bootstrap_key)
        assert "$40.00" in html, "the session's cap is not displayed"
    finally:
        api.gate.revoke_session(sess.session_id, tenant_id=tenant)


def test_another_tenants_session_is_not_listed(haldir_client, bootstrap_key) -> None:
    """The console is per-tenant, and this is the assertion that keeps it
    that way."""
    foreign, _ = _foreign_session("foreign-agent")

    html = _page(haldir_client, bootstrap_key)
    assert "foreign-agent" not in html, "another tenant's agent leaked into the page"
    assert foreign.session_id[:12] not in html


def test_recent_activity_shows_recorded_actions(haldir_client, bootstrap_key) -> None:
    tenant = _tenant(bootstrap_key)
    sess = api.gate.create_session(
        agent_id="activity-test-agent", tenant_id=tenant,
        scopes=["read"], spend_limit=10.0, ttl=600,
    )
    try:
        api.watch.log_action(
            session=sess, action="tool_call", tool="monitor.probe",
            cost_usd=0.5, tenant_id=tenant,
        )
        html = _page(haldir_client, bootstrap_key)
        assert "monitor.probe" in html, "the action is not in the activity feed"
        assert "Recent activity" in html
    finally:
        api.gate.revoke_session(sess.session_id, tenant_id=tenant)


def test_activity_feed_is_bounded(haldir_client, bootstrap_key) -> None:
    """The feed is a LIMIT query, not a full scan: a tenant with a million
    audit rows must not make the dashboard slower than one with ten."""
    tenant = _tenant(bootstrap_key)
    sess = api.gate.create_session(
        agent_id="bulk-agent", tenant_id=tenant,
        scopes=["read"], spend_limit=10.0, ttl=600,
    )
    try:
        for i in range(30):
            api.watch.log_action(session=sess, action="tool_call",
                                 tool=f"bulk.{i}", cost_usd=0.0, tenant_id=tenant)
        out = haldir_admin.build_overview(api.DB_PATH, tenant, watch=api.watch,
                                          tier_limits=api.TIER_LIMITS)
        assert len(out["audit"]["recent"]) <= 20, "the feed is not bounded"
    finally:
        api.gate.revoke_session(sess.session_id, tenant_id=tenant)


# ── The kill switch ──────────────────────────────────────────────────

def test_revoke_from_the_console_actually_revokes(haldir_client, bootstrap_key) -> None:
    """The button has to work. A kill switch that renders but does nothing
    is the worst possible outcome: an operator believes they stopped
    something that is still running."""
    tenant = _tenant(bootstrap_key)
    sess = api.gate.create_session(
        agent_id="revoke-me", tenant_id=tenant,
        scopes=["read"], spend_limit=10.0, ttl=600,
    )

    r = haldir_client.post("/admin/revoke",
                           data={"key": bootstrap_key, "session_id": sess.session_id})
    assert r.status_code == 302, r.data[:300]

    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    row = conn.execute("SELECT revoked FROM sessions WHERE session_id = ?",
                       (sess.session_id,)).fetchone()
    conn.close()
    assert int(row["revoked"]) == 1, "the session was not actually revoked"


def test_console_cannot_revoke_another_tenants_session(haldir_client, bootstrap_key) -> None:
    """The posted session_id is attacker-controlled, so the tenant check has
    to happen server-side. Without it, any key could kill any agent."""
    foreign, foreign_tenant = _foreign_session("foreign-agent")

    haldir_client.post("/admin/revoke",
                       data={"key": bootstrap_key,
                             "session_id": foreign.session_id})

    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    row = conn.execute("SELECT revoked FROM sessions WHERE session_id = ?",
                       (foreign.session_id,)).fetchone()
    conn.close()
    assert int(row["revoked"]) == 0, "a key revoked another tenant's session"


def test_revoke_requires_a_valid_key(haldir_client) -> None:
    r = haldir_client.post("/admin/revoke",
                           data={"key": "hld_not_a_real_key",
                                 "session_id": "whatever"})
    assert r.status_code == 401


def test_revoke_cascades_to_subagents(haldir_client, bootstrap_key) -> None:
    """Killing an orchestrator has to kill what it spawned. Otherwise the
    subagents keep working with credentials nobody is supervising, which is
    the situation the kill switch exists to end."""
    tenant = _tenant(bootstrap_key)
    parent = api.gate.create_session(
        agent_id="orchestrator", tenant_id=tenant,
        scopes=["read"], spend_limit=50.0, ttl=600,
    )
    child = api.gate.create_session(
        agent_id="subagent", tenant_id=tenant, scopes=["read"],
        spend_limit=10.0, ttl=300, parent_session_id=parent.session_id,
    )

    haldir_client.post("/admin/revoke",
                       data={"key": bootstrap_key,
                             "session_id": parent.session_id})

    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    row = conn.execute("SELECT revoked FROM sessions WHERE session_id = ?",
                       (child.session_id,)).fetchone()
    conn.close()
    assert int(row["revoked"]) == 1, "the subagent outlived its orchestrator"


# ── Escaping ─────────────────────────────────────────────────────────

def test_agent_and_tool_names_are_escaped(haldir_client, bootstrap_key) -> None:
    """An agent chooses its own tool names, and they land in an operator's
    browser. Unescaped, the audit log becomes a delivery mechanism for
    script injection into the console that is supposed to be watching it.
    """
    tenant = _tenant(bootstrap_key)
    payload = "<script>alert(1)</script>"
    sess = api.gate.create_session(
        agent_id=payload, tenant_id=tenant,
        scopes=["read"], spend_limit=10.0, ttl=600,
    )
    try:
        api.watch.log_action(session=sess, action="tool_call",
                             tool=f"evil{payload}", cost_usd=0.0, tenant_id=tenant)
        html = _page(haldir_client, bootstrap_key)
        assert "<script>alert(1)</script>" not in html, "unescaped script tag rendered"
        assert "&lt;script&gt;" in html, "the payload should appear escaped"
    finally:
        api.gate.revoke_session(sess.session_id, tenant_id=tenant)


def test_flagged_entries_surface_the_reason(haldir_client, bootstrap_key,
                                            flagged_entry) -> None:
    """A flag the operator cannot read is a flag they will ignore."""
    tenant = _tenant(bootstrap_key)
    sess = flagged_entry("flagged-agent", "rm.rf", "destructive-command")
    try:
        html = _page(haldir_client, bootstrap_key)
        assert "destructive-command" in html, "the flag reason is not shown"
    finally:
        api.gate.revoke_session(sess.session_id, tenant_id=tenant)


def test_flagged_reason_is_escaped(haldir_client, bootstrap_key,
                                   flagged_entry) -> None:
    """Flag reasons can quote the action that triggered them, so they are
    attacker-influenced too."""
    payload = "<img src=x onerror=alert(1)>"
    sess = flagged_entry("xss-flag-agent", "t", payload)
    try:
        html = _page(haldir_client, bootstrap_key)
        assert payload not in html, "unescaped flag reason rendered"
    finally:
        api.gate.revoke_session(sess.session_id, tenant_id=_tenant(bootstrap_key))
