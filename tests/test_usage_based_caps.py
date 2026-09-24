"""
Exceeding the allowance is billed on paid plans and refused on free.

Cloud and API are usage-based: a monthly fee buys an allowance of metered
actions, and usage past it is billed rather than blocked. That is a behaviour
change — every tier used to return 429 at its ceiling — so it needs pinning
in both directions:

  1. A paying tenant is not interrupted. The thing being metered is the audit
     record, so a 429 both stops an agent mid-task and leaves a hole in the
     trail at the exact moment something is happening. The customer who has
     already decided to pay is the last one to cut off.

  2. A free tenant still is. Free has no payment method behind it, so
     "billed, not blocked" would mean "free, unbounded" — the allowance has
     to keep being an allowance.

Run: python -m pytest tests/test_usage_based_caps.py -v
"""

from __future__ import annotations

import hashlib
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
import haldir_tiers  # noqa: E402


def _tenant_of(key: str) -> str:
    kh = hashlib.sha256(key.encode()).hexdigest()
    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    row = conn.execute("SELECT tenant_id FROM api_keys WHERE key_hash = ?",
                       (kh,)).fetchone()
    conn.close()
    return row["tenant_id"]


def _set_tier(tenant: str, tier: str) -> None:
    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    conn.execute("DELETE FROM subscriptions WHERE tenant_id = ?", (tenant,))
    conn.execute(
        "INSERT INTO subscriptions (tenant_id, tier, status, stripe_customer_id) "
        "VALUES (?, ?, 'active', ?)",
        (tenant, tier, f"cus_{tier}"),
    )
    conn.commit()
    conn.close()


def _set_usage(tenant: str, actions: int) -> None:
    from haldir_db import get_db
    month = time.strftime("%Y-%m")
    conn = get_db(api.DB_PATH)
    conn.execute(
        "INSERT INTO usage (tenant_id, month, action_count) VALUES (?, ?, ?) "
        "ON CONFLICT(tenant_id, month) DO UPDATE SET action_count = ?",
        (tenant, month, actions, actions),
    )
    conn.commit()
    conn.close()


@pytest.fixture
def billed_tenant(bootstrap_key):
    """The bootstrap tenant, upgraded, with its usage under our control."""
    from haldir_db import get_db
    tenant = _tenant_of(bootstrap_key)
    conn = get_db(api.DB_PATH)
    before = conn.execute("SELECT * FROM subscriptions WHERE tenant_id = ?",
                          (tenant,)).fetchall()
    conn.close()

    yield tenant

    conn = get_db(api.DB_PATH)
    conn.execute("DELETE FROM subscriptions WHERE tenant_id = ?", (tenant,))
    for row in before:
        conn.execute(
            "INSERT INTO subscriptions (tenant_id, tier, status, stripe_customer_id) "
            "VALUES (?, ?, ?, ?)",
            (row["tenant_id"], row["tier"], row["status"], row["stripe_customer_id"]),
        )
    conn.execute("DELETE FROM usage WHERE tenant_id = ?", (tenant,))
    conn.commit()
    conn.close()


def _call(client, key):
    return client.get("/v1/audit?limit=1",
                      headers={"Authorization": f"Bearer {key}"})


# ── A paying tenant keeps working ────────────────────────────────────

def test_the_metered_plan_is_never_blocked(haldir_client, bootstrap_key, billed_tenant) -> None:
    """The whole point of usage billing: the work continues and the meter
    keeps running.

    There is no allowance on this plan, so there is no ceiling to reach —
    five million calls in a month is a large bill, not an error.
    """
    _set_tier(billed_tenant, "usage")
    _set_usage(billed_tenant, 5_000_000)

    r = _call(haldir_client, bootstrap_key)
    assert r.status_code == 200, (
        f"a metered tenant at 5,000,000 calls got {r.status_code}; there is "
        f"no allowance on this plan, so nothing can be exceeded"
    )

    # And the whole of it is reported as billable, not merely tolerated.
    assert int(r.headers["X-RateLimit-Monthly-Over-By"]) == 5_000_000


def test_free_is_still_blocked_at_its_allowance(haldir_client, bootstrap_key, billed_tenant) -> None:
    """No card on file, so no overage. Otherwise the free tier is the
    unlimited tier."""
    _set_tier(billed_tenant, "free")
    limit = haldir_tiers.TIERS["free"]["actions_per_month"]
    _set_usage(billed_tenant, limit + 1)

    r = _call(haldir_client, bootstrap_key)
    assert r.status_code == 429, (
        "a free tenant past its allowance was allowed through, so the free "
        "allowance is not an allowance"
    )
    body = r.get_json()
    assert body.get("error") == "monthly_quota_exceeded" or "quota" in str(body).lower()


def test_usage_is_reported_in_the_usage_headers(haldir_client, bootstrap_key, billed_tenant) -> None:
    """A customer cannot decide about a bill they cannot see."""
    _set_tier(billed_tenant, "usage")
    _set_usage(billed_tenant, 250_000)

    r = _call(haldir_client, bootstrap_key)
    assert r.status_code == 200
    assert int(r.headers["X-RateLimit-Monthly-Over-By"]) == 250_000

    expected = haldir_tiers.overage_cost("usage", 250_000)
    assert float(r.headers["X-RateLimit-Monthly-Overage-USD"]) == pytest.approx(expected)


def test_the_metered_plan_reports_no_limit_header(haldir_client, bootstrap_key, billed_tenant) -> None:
    """Absent, not zero.

    A plan with no allowance has no limit and no remaining. Emitting `0` for
    both says the account is already out of quota — and a client that reads
    those headers would back off for no reason, which is a worse failure than
    not sending them at all.
    """
    _set_tier(billed_tenant, "usage")
    _set_usage(billed_tenant, 10)

    r = _call(haldir_client, bootstrap_key)
    assert r.status_code == 200
    assert "X-RateLimit-Monthly-Limit" not in r.headers
    assert "X-RateLimit-Monthly-Remaining" not in r.headers
    # The count itself is still reported — that is the invoice.
    assert int(r.headers["X-RateLimit-Monthly-Used"]) == 10
    assert int(r.headers["X-RateLimit-Monthly-Over-By"]) == 10


# ── The overview reports it too ──────────────────────────────────────

def test_overview_exposes_the_metered_cost(haldir_client, bootstrap_key, billed_tenant) -> None:
    """The dashboard is where an operator would look, so it has to carry the
    same number the limiter is acting on.

    With no allowance, every call is billable — so `overage_actions` is the
    whole month's usage, and an implementation that computed
    `max(0, used - allowance)` with no allowance would report zero for the
    plan whose entire revenue this is.
    """
    import haldir_admin

    _set_tier(billed_tenant, "usage")
    _set_usage(billed_tenant, 1_000)

    out = haldir_admin.build_overview(api.DB_PATH, billed_tenant,
                                      watch=api.watch, tier_limits=api.TIER_LIMITS)
    usage = out["usage"]
    assert usage["overage_actions"] == 1_000
    assert usage["metered"] is True
    assert usage["actions_limit"] is None
    assert usage["overage_usd"] == pytest.approx(
        haldir_tiers.overage_cost("usage", 1_000)
    )


def test_overview_says_not_billable_on_free(haldir_client, bootstrap_key, billed_tenant) -> None:
    """None, not 0.0 — "not billable" and "costs nothing" are different
    statements, and a UI that renders the second when it means the first
    tells the customer their overage is free."""
    import haldir_admin

    _set_tier(billed_tenant, "free")
    limit = haldir_tiers.TIERS["free"]["actions_per_month"]
    _set_usage(billed_tenant, limit + 1_000)

    out = haldir_admin.build_overview(api.DB_PATH, billed_tenant,
                                      watch=api.watch, tier_limits=api.TIER_LIMITS)
    assert out["usage"]["overage_usd"] is None
    assert out["usage"]["metered"] is False
