"""Capability cards: opt-in, capability-only, and withdrawable.

A card is the first part of Haldir that faces outward, so these tests are
mostly about what it *cannot* become:

  * the public projection carries only what its own list names — a column
    added to the table later cannot leak by default (the centrepiece test);
  * no operational field reaches it, even for an agent with spend, sessions
    and flags on the record;
  * opt-in is per agent, and withdrawing *deletes* rather than hiding;
  * a card cannot be published for an agent the register has never seen, and
    one tenant cannot see, change, or withdraw another's.

Run: python -m pytest tests/test_cards.py -v
"""

from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
import haldir_cards  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Exactly what a public card is allowed to carry. A whitelist on purpose: a
#: blacklist ("remove the private fields") is one forgotten removal away from
#: publishing spend.
PUBLIC_CARD_FIELDS = {
    "card_id", "display_name", "description", "capabilities",
    "contact_url", "published_at", "updated_at",
}


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture(autouse=True)
def _clean_cards():
    """Cards persist in the session-scoped database, so one test's published
    card is the next test's unexpected index entry. Same shape as the OAuth
    suite's cleanup fixture."""
    from haldir_db import get_db
    def _clear():
        conn = get_db(api.DB_PATH)
        try:
            conn.execute("DELETE FROM agent_cards")
            conn.commit()
        finally:
            conn.close()
    _clear()
    yield
    _clear()


@pytest.fixture
def tenant_of(haldir_client, bootstrap_key) -> str:
    return haldir_client.get(
        "/v1/admin/overview", headers=_auth(bootstrap_key)
    ).get_json()["tenant_id"]


def _agent_with_activity(name: str, tenant: str, *, spend: float = 0.0):
    """An agent with a real record behind it — the thing a card must not
    summarise."""
    session = api.gate.create_session(
        name, scopes=["spend"], tenant_id=tenant, spend_limit=spend,
    )
    api.watch.log_action(session, tool="stripe", action="charge",
                         cost_usd=1.25, tenant_id=tenant)
    return session


def _publish(client, key: str, agent_id: str, **overrides) -> dict:
    body = {
        "display_name": "Ledger Bot",
        "description": "Reconciles invoices and schedules payments.",
        "capabilities": ["read invoices", "schedule payment"],
        "contact_url": "https://example.com/ledger-bot",
    }
    body.update(overrides)
    return client.post(f"/v1/agents/{agent_id}/card", json=body, headers=_auth(key))


@pytest.fixture(autouse=True)
def _release_rate_limit_budget():
    """These tests make real calls against the shared bootstrap key, and the
    suite's per-key hourly limiter counts them cumulatively. Without releasing
    the budget, modules that run later get 429s for reasons that have nothing
    to do with them — which is exactly what happened when this file was added.
    `fresh_counter` in conftest resets before a test; this releases after one,
    which is what a module adding load owes the rest of the suite.
    """
    yield
    import api  # imported here: not every module in this file needs it at import time
    api._rate_limits.clear()


# ── The projection ─────────────────────────────────────────────────────

def test_the_public_card_carries_exactly_the_named_fields(
    haldir_client, bootstrap_key, tenant_of
) -> None:
    """The property that matters most: everything else in this file is
    convenience, this one is the promise."""
    session = _agent_with_activity("ledger-bot", tenant_of, spend=50.0)
    assert _publish(haldir_client, bootstrap_key, "ledger-bot").status_code == 201

    cards = haldir_client.get("/.well-known/agents.json").get_json()["cards"]
    card = next(c for c in cards if c["display_name"] == "Ledger Bot")
    assert set(card) == PUBLIC_CARD_FIELDS

    # The record must not leak *by value*. Substrings would be the wrong test:
    # the operator's own contact URL may name their own agent, and that is
    # theirs to publish.
    everything = " ".join(str(v) for v in card.values()).lower()
    assert tenant_of.lower() not in everything, "the tenant id is on the card"
    assert session.session_id.lower() not in everything, "the session id is on the card"
    # Compared as numbers, not substrings: "50" appears inside the published_at
    # epoch, and a test that fails on a timestamp is a test nobody trusts.
    numbers = [v for v in card.values() if isinstance(v, (int, float))]
    assert 50.0 not in numbers and 1.25 not in numbers, (
        "a spend figure from the record is on the card"
    )


def test_publishing_an_agent_with_no_activity_is_still_opt_in_per_agent(
    haldir_client, bootstrap_key, tenant_of
) -> None:
    _agent_with_activity("quiet-bot", tenant_of)
    other = api.gate.create_session("unlisted-bot", scopes=["read"], tenant_id=tenant_of)
    assert other is not None
    assert _publish(haldir_client, bootstrap_key, "quiet-bot").status_code == 201

    names = [c["display_name"] for c in
             haldir_client.get("/.well-known/agents.json").get_json()["cards"]]
    assert names == ["Ledger Bot"], "only the agent that was published appears"


def test_withdrawing_deletes_the_row(haldir_client, bootstrap_key, tenant_of) -> None:
    """'Hidden' and 'gone' are different promises to an operator, and only one
    of them is worth making."""
    from haldir_db import get_db

    _agent_with_activity("ledger-bot", tenant_of)
    _publish(haldir_client, bootstrap_key, "ledger-bot")
    assert haldir_client.delete(
        "/v1/agents/ledger-bot/card", headers=_auth(bootstrap_key)
    ).status_code == 200

    assert haldir_client.get("/.well-known/agents.json").get_json()["count"] == 0
    conn = get_db(api.DB_PATH)
    row = conn.execute("SELECT COUNT(*) FROM agent_cards").fetchone()
    conn.close()
    assert row[0] == 0, "the row still exists — unpublish must delete, not flag"


# ── Validation ─────────────────────────────────────────────────────────

def test_a_card_needs_a_display_name(haldir_client, bootstrap_key, tenant_of) -> None:
    _agent_with_activity("ledger-bot", tenant_of)
    r = _publish(haldir_client, bootstrap_key, "ledger-bot", display_name="")
    assert r.status_code == 400
    assert r.get_json()["code"] == "invalid_card"


def test_a_contact_url_must_be_http_or_https(haldir_client, bootstrap_key, tenant_of) -> None:
    """Displayed, not fetched — so this is not an SSRF guard but a phishing
    guard: a public directory rendering `javascript:` is a link someone else's
    users click."""
    _agent_with_activity("ledger-bot", tenant_of)
    for bad in ("javascript:alert(1)", "file:///etc/passwd", "not a url"):
        r = _publish(haldir_client, bootstrap_key, "ledger-bot", contact_url=bad)
        assert r.status_code == 400, f"{bad!r} was accepted"


def test_a_card_cannot_be_published_for_an_agent_nobody_has_seen(
    haldir_client, bootstrap_key
) -> None:
    r = _publish(haldir_client, bootstrap_key, "never-existed")
    assert r.status_code == 404
    assert r.get_json()["code"] == "not_found"


def test_republishing_updates_rather_than_duplicating(
    haldir_client, bootstrap_key, tenant_of
) -> None:
    _agent_with_activity("ledger-bot", tenant_of)
    first = _publish(haldir_client, bootstrap_key, "ledger-bot").get_json()
    second = _publish(haldir_client, bootstrap_key, "ledger-bot",
                      display_name="Ledger Bot v2").get_json()
    assert second["card_id"] == first["card_id"], "the card id is stable across updates"
    assert second["updated"] is True
    cards = haldir_client.get("/.well-known/agents.json").get_json()["cards"]
    assert [c["display_name"] for c in cards] == ["Ledger Bot v2"]


# ── Tenancy ────────────────────────────────────────────────────────────

def test_one_tenant_cannot_see_or_withdraw_anothers_card(haldir_client, bootstrap_key) -> None:
    other_session = api.gate.create_session("their-bot", scopes=["read"], tenant_id="t-somebody")
    assert other_session is not None
    haldir_cards.publish(api.DB_PATH, "t-somebody", "their-bot",
                         display_name="Their Bot")

    # The owner's view is scoped: this tenant has no card for that agent.
    r = haldir_client.get("/v1/agents/their-bot/card", headers=_auth(bootstrap_key))
    assert r.status_code == 404
    # And withdrawing someone else's agent is the same 404 — not a different
    # answer that would confirm the agent exists elsewhere.
    r = haldir_client.delete("/v1/agents/their-bot/card", headers=_auth(bootstrap_key))
    assert r.status_code == 404
    # Their card is still published.
    assert any(c["display_name"] == "Their Bot"
               for c in haldir_client.get("/.well-known/agents.json").get_json()["cards"])
    haldir_cards.unpublish(api.DB_PATH, "t-somebody", "their-bot")


# ── The register knows what is discoverable ────────────────────────────

def test_the_register_marks_discoverable_agents(
    haldir_client, bootstrap_key, tenant_of
) -> None:
    _agent_with_activity("ledger-bot", tenant_of)
    _agent_with_activity("private-bot", tenant_of)
    _publish(haldir_client, bootstrap_key, "ledger-bot")

    register = haldir_client.get("/v1/agents", headers=_auth(bootstrap_key)).get_json()
    by_id = {a["agent_id"]: a for a in register["agents"]}
    assert by_id["ledger-bot"]["card_id"]
    assert by_id["private-bot"]["card_id"] is None
    assert register["summary"]["discoverable_agents"] == 1
    # Both are agents — discoverability does not change what something is.
    assert by_id["ledger-bot"]["kind"] == "agent"


def test_operators_and_system_are_principals_not_agents(
    haldir_client, bootstrap_key, tenant_of
) -> None:
    """`admin:<prefix>` is how `_audit_admin` attributes an operator's action,
    and `system` is the deployment's own bookkeeping. They acted, so they are
    in the register — but a register of *AI systems* that counts a person's
    key as an agent is wrong in the direction nobody notices."""
    _agent_with_activity("ledger-bot", tenant_of)
    _publish(haldir_client, bootstrap_key, "ledger-bot")  # writes an admin: entry

    register = haldir_client.get("/v1/agents", headers=_auth(bootstrap_key)).get_json()
    kinds = {a["agent_id"]: a["kind"] for a in register["agents"]}
    assert kinds["ledger-bot"] == "agent"

    # The summary counts the two kinds separately, and the register this test
    # shares a database with has agents from other tests in it — so assert the
    # relationship rather than totals.
    summary = register["summary"]
    assert summary["agents"] == sum(1 for a in register["agents"] if a["kind"] == "agent")
    assert summary["principals"] == sum(1 for a in register["agents"] if a["kind"] == "principal")
    assert summary["entries"] == len(register["agents"])
    assert summary["agents"] + summary["principals"] == summary["entries"]
    # Publishing wrote an `admin:` entry, and it is not counted as an agent.
    assert summary["principals"] >= 1, "the admin action should appear as a principal"
    assert any(a.startswith("admin:") for a in kinds), (
        "publishing should have left an admin: entry in the register"
    )


# ── The two definitions of the table ───────────────────────────────────

def test_the_migration_and_the_store_create_the_same_table() -> None:
    """Two definitions of one table is how `approval_requests` ended up
    without its tenant column on one path. The store creates its own table so
    a bare test database works; the migration creates it for deployments; this
    asserts they agree rather than trusting that they do."""
    migration = open(os.path.join(ROOT, "migrations", "010_agent_cards.sql")).read()
    block = re.search(r"CREATE TABLE IF NOT EXISTS agent_cards \((.*?)\n\);",
                      migration, re.S)
    assert block, "the migration no longer creates agent_cards"
    migration_cols = set(re.findall(r"^\s*(\w+)\s+[A-Z]", block.group(1), re.M))

    store_block = re.search(r"CREATE TABLE IF NOT EXISTS agent_cards \((.*?)\n\s*\)",
                            haldir_cards._DDL, re.S)
    assert store_block, "the store no longer creates agent_cards"
    store_cols = set(re.findall(r"^\s*(\w+)\s+[A-Z]", store_block.group(1), re.M))

    assert migration_cols == store_cols, (
        f"migration and store disagree: migration-only {sorted(migration_cols - store_cols)}, "
        f"store-only {sorted(store_cols - migration_cols)}"
    )
    assert "tenant_id" in store_cols, "the tenant column is the scoping rule"
