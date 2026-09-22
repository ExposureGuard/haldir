"""
Every surface that states a plan limit has to state the same one.

What went wrong: the numbers were written down in five places and had drifted
into three different answers.

    api.py               Pro = 10 agents
    haldir_admin.py      Pro = 10 agents (a copy of the above)
    landing/index.html   Pro = 25 agents, $99
    api.py /pricing      Pro = 10 agents, $49
    Stripe price id      whatever the deploy set

So a customer could read "$99, 25 agents" on the marketing site and "$49,
10 agents" inside the product, and be capped at 10 either way. Nothing caught
it because each copy was individually plausible and nothing compared them.

The fix was structural — one table in haldir_tiers, every surface derived from
it — but structure alone does not stay fixed. These tests are what make the
next drift fail in CI rather than in front of a customer.

Run: python -m pytest tests/test_tiers.py -v
"""

from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import haldir_tiers  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LANDING = os.path.join(_ROOT, "landing", "index.html")


# ── One table, no copies ─────────────────────────────────────────────

def test_the_api_table_is_the_shared_table() -> None:
    """api.TIER_LIMITS must be the shared table itself, not a copy of it.

    A copy is how the drift started: an equal-looking dict that quietly stops
    being equal the moment one side is edited.
    """
    import api
    assert api.TIER_LIMITS is haldir_tiers.TIERS, (
        "api.TIER_LIMITS is a separate object from haldir_tiers.TIERS, so the "
        "two can drift apart again"
    )


def test_the_admin_table_is_the_shared_table() -> None:
    import haldir_admin
    assert haldir_admin._DEFAULT_TIER_LIMITS is haldir_tiers.TIERS


def test_haldir_tiers_imports_nothing_heavy() -> None:
    """It is imported by a pure module specifically so nothing has to
    re-declare the table to avoid pulling in Flask."""
    import ast
    src = open(os.path.join(_ROOT, "haldir_tiers.py")).read()
    imported = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= {"__future__", "typing"}, (
        f"haldir_tiers pulls in {sorted(imported - {'__future__', 'typing'})}, "
        f"which defeats the reason it can be the single definition"
    )


# ── The plans have to be usable ──────────────────────────────────────

def test_a_paid_plan_can_run_the_agents_it_allows() -> None:
    """The bug the numbers had: Pro allowed 10 agents and 50,000 API calls.

    One agent costs 86,400 API calls a month on the module's stated
    assumptions. So the plan ran out less than two-thirds of the way through a
    single agent's month while advertising ten, and would have hit its ceiling
    mid-task — for an agent whose entire purpose is to be audited. A plan
    whose allowance cannot run its own agent count is not a plan, it is a
    trap, and it was invisible because the two numbers were never compared.

    Free is deliberately exempt, and the exemption is narrow: it is a
    time-boxed trial, so its allowance is meant to run out — a free tier that
    sustains a production agent is not a free tier, it is a free product. The
    distinction that matters is that Pro is *sold* as "for teams running
    multiple agents in production", so its allowance has to reach its agent
    count. Free is sold as "get started".

    If free is ever repositioned as a usable-forever tier rather than a
    trial, this exemption has to go with it.
    """
    # The per-agent figure comes from the module, not from a second copy
    # here: sizing the plan against one number and testing it against another
    # is the drift this whole file exists to prevent.
    per_agent = haldir_tiers.api_calls_per_agent_per_month()

    for name, plan in haldir_tiers.TIERS.items():
        if name == "free":
            continue
        agents = plan["agents"]
        if agents >= 999_999:      # unlimited: nothing to be consistent with
            continue
        needed = agents * per_agent
        assert plan["actions_per_month"] >= needed, (
            f"{name} allows {agents} agents but only "
            f"{plan['actions_per_month']:,} API calls/month; running all of them "
            f"at one API call a minute needs {needed:,}"
        )


def test_free_has_no_overage_and_the_paid_plans_do() -> None:
    """Free has no payment method behind it, so it must stop at the
    allowance; Pro carries a subscription, so it must not."""
    assert haldir_tiers.is_hard_capped("free") is True
    assert haldir_tiers.is_metered("pro") is True
    assert haldir_tiers.is_metered("enterprise") is False


def test_unknown_tier_falls_back_to_free_not_enterprise() -> None:
    """A subscription row written by an older version, or a typo in a Stripe
    price mapping, must not silently become the unlimited plan."""
    assert haldir_tiers.limits("platinum") is haldir_tiers.TIERS["free"]
    assert haldir_tiers.limits("") is haldir_tiers.TIERS["free"]
    assert haldir_tiers.is_hard_capped("nonsense") is True


# ── Overage arithmetic ───────────────────────────────────────────────

def test_overage_is_billed_at_the_stated_rate() -> None:
    rate = haldir_tiers.TIERS["pro"]["overage_usd_per_action"]
    assert haldir_tiers.overage_cost("pro", 1_000_000) == round(1_000_000 * rate, 6)


def test_overage_is_none_rather_than_zero_when_uncapped() -> None:
    """None means 'not billable', and callers have to treat it that way.
    Returning 0.0 would read as 'free', which is a different thing."""
    assert haldir_tiers.overage_cost("free", 500) is None
    assert haldir_tiers.overage_cost("enterprise", 10**9) is None


def test_no_overage_charge_below_the_allowance() -> None:
    assert haldir_tiers.overage_cost("pro", 0) is None
    assert haldir_tiers.overage_cost("pro", -5) is None


def test_overage_costs_more_than_included_usage() -> None:
    """Otherwise a customer is better off exceeding the plan than buying it,
    and the tier above is never worth upgrading to."""
    plan = haldir_tiers.TIERS["pro"]
    included_rate = plan["price_usd_month"] / plan["actions_per_month"]
    assert plan["overage_usd_per_action"] > included_rate, (
        "overage is cheaper than the included rate, so nobody would ever "
        "upgrade — they would just run past the cap"
    )


# ── The marketing copy ───────────────────────────────────────────────

def _landing_offers() -> dict[str, str]:
    html = open(_LANDING, encoding="utf-8").read()
    blocks = re.findall(r'\{"@type": "Offer",[^}]*\}', html)
    offers = {}
    for b in blocks:
        try:
            obj = json.loads(b)
        except json.JSONDecodeError:
            continue
        offers[obj.get("name", "").lower()] = obj.get("description", "")
    return offers


def test_landing_page_states_the_real_allowances() -> None:
    """The copy is prose, so it cannot be generated — but it can be checked."""
    offers = _landing_offers()
    assert offers, "no Offer blocks found in the landing page"

    for name in ("free", "pro"):
        plan = haldir_tiers.TIERS[name]
        desc = offers.get(name, "")
        assert desc, f"landing page has no Offer for {name}"

        allowed = f"{plan['actions_per_month']:,}"
        assert allowed in desc, (
            f"the landing page says '{desc}' for {name}, but the plan allows "
            f"{allowed} actions/month"
        )

        agents = plan["agents"]
        if agents < 999_999:
            assert f"{agents} agents" in desc or f"{agents} agent" in desc or "single agent" in desc, (
                f"the landing page does not state the {agents}-agent limit for "
                f"{name}: '{desc}'"
            )


def test_landing_page_price_matches_the_table() -> None:
    offers = _landing_offers()
    html = open(_LANDING, encoding="utf-8").read()
    blocks = re.findall(r'\{"@type": "Offer",[^}]*\}', html)
    prices = {}
    for b in blocks:
        try:
            obj = json.loads(b)
        except json.JSONDecodeError:
            continue
        prices[obj.get("name", "").lower()] = obj.get("price")

    pro = haldir_tiers.TIERS["pro"]["price_usd_month"]
    assert prices.get("pro") == str(pro), (
        f"landing page prices Pro at ${prices.get('pro')} but the table says ${pro}"
    )
    assert offers, "no offers parsed"


def test_the_in_product_pricing_page_renders_from_the_table(client=None) -> None:
    """The page that used to say $49 for a $99 plan.

    Rendered and inspected rather than read: the point is what a customer
    sees, and the numbers are generated now.
    """
    import api

    c = client or api.app.test_client()
    r = c.get("/pricing")
    assert r.status_code == 200
    html = r.get_data(as_text=True)

    assert "{TIER_CARDS}" not in html, "the placeholder was never substituted"

    for name in ("free", "pro", "enterprise"):
        plan = haldir_tiers.TIERS[name]
        price = plan["price_usd_month"]
        if price:
            assert f"${price:,}" in html, (
                f"/pricing does not show the ${price:,} price for {name}"
            )

    pro = haldir_tiers.TIERS["pro"]
    assert f"{pro['actions_per_month']:,}" in html, (
        "/pricing does not state Pro's action allowance"
    )
    assert f"{pro['agents']} agents" in html, "/pricing does not state Pro's agent limit"

    # And the numbers it replaced are gone, not merely joined by the new ones.
    assert "$49" not in html, "/pricing still advertises the old $49"
    assert "50,000 actions" not in html, "/pricing still advertises the old allowance"
