"""The assurance dimension of the plan table: declared, and enforced.

The register and the framework mappings are what an assurance buyer buys, so
which frameworks a plan includes, how long evidence is kept, and whether
delivery runs on a schedule are plan attributes — and, more importantly, they
are **enforced**. A plan card that promises framework coverage the product
gives everyone is a promise that means nothing, and the two can only be kept
in step by one table feeding both.

The last two tests are the ones that matter: a free tenant's pack contains the
SOC 2 mapping and names the two it does not include, and a tenant with an
active subscription gets all three.

Run: python -m pytest tests/test_assurance_plans.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
import haldir_frameworks  # noqa: E402
import haldir_tiers  # noqa: E402

TIERS = ("free", "usage", "enterprise")


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


# ── The table ──────────────────────────────────────────────────────────

def test_every_plan_declares_its_assurance_entitlements() -> None:
    for tier in TIERS:
        ent = haldir_tiers.assurance(tier)
        assert ent["frameworks"], f"{tier} includes no framework at all"
        assert set(ent) >= {"frameworks", "evidence_retention_days", "scheduled_delivery"}


def test_a_higher_plan_includes_everything_a_lower_one_does() -> None:
    """Entitlements only ever grow with the plan. A cheaper tier holding a
    mapping the pricier one lacks is a bug that reads as a downgrade."""
    free = set(haldir_tiers.assurance("free")["frameworks"])
    usage = set(haldir_tiers.assurance("usage")["frameworks"])
    enterprise = set(haldir_tiers.assurance("enterprise")["frameworks"])
    assert free <= usage <= enterprise
    assert free < usage, "the paid plan has to include something the free one does not"


def test_retention_is_a_window_or_custom_never_zero() -> None:
    """`None` means custom. `0` would read as a plan that keeps nothing —
    and would quietly satisfy anyone who checked `if days:`."""
    for tier in TIERS:
        days = haldir_tiers.assurance(tier)["evidence_retention_days"]
        assert days is None or days > 0, f"{tier} retention is {days!r}"


def test_the_retired_name_carries_the_same_entitlements() -> None:
    assert haldir_tiers.assurance("pro") == haldir_tiers.assurance("usage")


def test_every_entitled_framework_is_one_that_exists() -> None:
    """A typo here is a plan promising a mapping the product cannot render."""
    known = set(haldir_frameworks.FRAMEWORKS)
    for tier in TIERS:
        unknown = set(haldir_tiers.assurance(tier)["frameworks"]) - known
        assert not unknown, f"{tier} entitles {sorted(unknown)}, which no framework defines"


def test_the_card_names_every_framework_it_lists() -> None:
    """The display names live in `haldir_tiers` because it may import only
    `typing` — importing `haldir_frameworks` for the labels would defeat the
    reason the plan table can be the single definition. This keeps the copy in
    step instead: a framework with no card name renders as its raw id, which
    is how 'iso_42001' ends up on a pricing page."""
    for tier in TIERS:
        for framework_id in haldir_tiers.assurance(tier)["frameworks"]:
            assert framework_id in haldir_tiers._FRAMEWORK_CARD_NAMES, (
                f"{framework_id} has no display name for the plan cards"
            )
            # And the reverse: every name must belong to a real framework.
    for framework_id in haldir_tiers._FRAMEWORK_CARD_NAMES:
        assert framework_id in haldir_frameworks.FRAMEWORKS


def test_the_cards_render_the_entitlements() -> None:
    free_lines = haldir_tiers.feature_lines("free")
    usage_lines = haldir_tiers.feature_lines("usage")
    assert any("SOC 2" in line for line in free_lines)
    assert any("EU AI Act" in line for line in usage_lines)
    assert any("30-day evidence retention" == line for line in free_lines)
    assert any("90-day evidence retention" == line for line in usage_lines)
    assert any("Custom evidence retention" in line for line in haldir_tiers.feature_lines("enterprise"))
    # Scheduled delivery is a paid entitlement; the free card must not claim it.
    assert not any("Scheduled evidence delivery" in line for line in free_lines)


# ── Enforcement ────────────────────────────────────────────────────────

def _make_tenant_subscribed(tenant: str, tier: str = "usage") -> None:
    """What the Stripe webhook does when a checkout completes: an active
    subscription row, which is the only thing that raises a tenant's tier.
    (POST /v1/keys always mints a *free* key on purpose — a key cannot
    self-assign a plan.)"""
    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO subscriptions "
        "(tenant_id, stripe_customer_id, stripe_subscription_id, tier, status, "
        " current_period_end, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 'active', ?, ?, ?)",
        (tenant, "cus_test", "sub_test", tier, 0.0, 0.0, 0.0),
    )
    conn.commit()
    conn.close()


def test_a_free_tenant_sees_its_frameworks_and_is_told_what_it_is_missing(
    haldir_client, bootstrap_key
) -> None:
    pack = haldir_client.get("/v1/compliance/evidence", headers=_auth(bootstrap_key)).get_json()
    assert sorted(pack["frameworks"]) == ["soc2"]
    assert sorted(pack["frameworks_excluded"]) == ["eu_ai_act", "iso_42001"]

    markdown = haldir_client.get(
        "/v1/compliance/evidence?format=markdown", headers=_auth(bootstrap_key)
    ).data.decode()
    assert "Not included in this plan" in markdown
    assert "EU AI Act" in markdown  # named as excluded, not merely absent
    # And the mapping itself is genuinely absent from the rendered document.
    assert "Article 12(1)" not in markdown

    score = haldir_client.get("/v1/compliance/score", headers=_auth(bootstrap_key)).get_json()
    assert sorted(score["frameworks"]) == ["soc2"]


def test_a_subscribed_tenant_gets_all_three(haldir_client, bootstrap_key) -> None:
    tenant = haldir_client.get(
        "/v1/admin/overview", headers=_auth(bootstrap_key)
    ).get_json()["tenant_id"]
    _make_tenant_subscribed(tenant)  # then re-request

    pack = haldir_client.get("/v1/compliance/evidence", headers=_auth(bootstrap_key)).get_json()
    assert sorted(pack["frameworks"]) == ["eu_ai_act", "iso_42001", "soc2"]
    assert "frameworks_excluded" not in pack

    markdown = haldir_client.get(
        "/v1/compliance/evidence?format=markdown", headers=_auth(bootstrap_key)
    ).data.decode()
    assert "Article 26(6)" in markdown
    assert "Not included in this plan" not in markdown


def test_the_manifest_digest_matches_the_filtered_pack(haldir_client, bootstrap_key) -> None:
    """The manifest is the short document an auditor keeps. If it filtered
    differently from the pack, its digest would disagree with the full pack's
    and the verification instructions would be wrong."""
    full = haldir_client.get("/v1/compliance/evidence", headers=_auth(bootstrap_key)).get_json()
    manifest = haldir_client.get(
        "/v1/compliance/evidence/manifest", headers=_auth(bootstrap_key)
    ).get_json()
    assert manifest["signatures"]["digest"] == full["signatures"]["digest"]


@pytest.fixture(autouse=True)
def _cleanup_subscription():
    """The subscription row outlives the test if it is not removed — the DB is
    session-scoped, and a tenant left subscribed would change what every later
    test sees."""
    yield
    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    conn.execute("DELETE FROM subscriptions WHERE stripe_customer_id = 'cus_test'")
    conn.commit()
    conn.close()
