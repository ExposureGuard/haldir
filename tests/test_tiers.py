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

def test_only_the_free_plan_caps_agents() -> None:
    """Agent count was a plan dimension when a plan had to be sized to it.

    The bug that shape produced is worth remembering: Pro once allowed 10
    agents and 50,000 API calls a month. One agent costs 86,400 of them
    (see api_calls_per_agent_per_month), so the plan ran out less than
    two-thirds of the way through a single agent's month while advertising
    ten — invisible because the two numbers were never compared.

    One metered rate and no subscription removed the shape. There is no
    allowance for a cap to protect, so the paid plan caps neither agents nor
    calls; it charges per call. Free still caps agents, and has to — a
    runaway agent burns its 10,000 calls in hours, and usage alone cannot
    express "do not run a fleet on somebody else's unmetered allowance".

    Asserted as an equality rather than looped over, because a loop over an
    empty set passes. This test would otherwise have gone quietly vacuous the
    moment the paid plan stopped having an allowance.
    """
    capped = sorted(
        name for name, plan in haldir_tiers.TIERS.items()
        if plan["agents"] < 999_999
    )
    assert capped == ["free"], (
        f"these plans cap agents: {capped}. A plan that caps agents also "
        f"needs an allowance sized to run them — one agent costs "
        f"{haldir_tiers.api_calls_per_agent_per_month():,} API calls a month. "
        f"Add the sizing check back for the new plan rather than exempting it."
    )


def test_the_metered_plan_includes_no_calls() -> None:
    """None, not 0.

    Zero would render on the pricing card as an allowance of zero, and in the
    rate-limit headers as `remaining: 0` — a limit that reads as already
    exceeded rather than as one that does not exist. A client seeing that
    backs off for no reason.
    """
    assert haldir_tiers.limits("usage")["actions_per_month"] is None
    assert haldir_tiers.is_metered("usage") is True
    assert haldir_tiers.is_hard_capped("usage") is False


def test_free_has_no_overage_and_the_metered_plan_does() -> None:
    """Free has no payment method behind it, so it must stop at the
    allowance; the metered plan is billed, so it must not."""
    assert haldir_tiers.is_hard_capped("free") is True
    assert haldir_tiers.is_metered("usage") is True
    assert haldir_tiers.is_metered("enterprise") is False


def test_unknown_tier_falls_back_to_free_not_enterprise() -> None:
    """A subscription row written by an older version, or a typo in a Stripe
    price mapping, must not silently become the unlimited plan."""
    assert haldir_tiers.limits("platinum") is haldir_tiers.TIERS["free"]
    assert haldir_tiers.limits("") is haldir_tiers.TIERS["free"]
    assert haldir_tiers.is_hard_capped("nonsense") is True


def test_the_retired_pro_name_resolves_to_its_replacement() -> None:
    """The failure worse than a stale plan name: dropping a paying tenant
    onto free.

    `subscriptions` rows written while the plan was a $99/month subscription
    still say "pro". Through the usual fallback that resolves to free —
    a 10,000-call hard cap applied mid-month to a paying customer, with no
    error raised and nothing that would notice.
    """
    assert haldir_tiers.limits("pro") is haldir_tiers.TIERS["usage"]
    assert haldir_tiers.is_metered("pro") is True
    assert haldir_tiers.is_hard_capped("pro") is False


def test_no_caller_looks_up_a_tier_without_the_alias() -> None:
    """A direct table lookup skips RENAMED_TIERS and undoes the test above.

    api.py had three of these and haldir_admin.py had one:
    `TIER_LIMITS.get(tier, TIER_LIMITS["free"])` hands a "pro" tenant free's
    one-agent cap while the rate limiter bills them as usage — two answers
    for one tenant, and the stricter one is the one they see.
    """
    offenders = []
    for path in ("api.py", "haldir_admin.py"):
        src = open(os.path.join(_ROOT, path), encoding="utf-8").read()
        for line_no, line in enumerate(src.splitlines(), 1):
            # Comments are stripped first. The fix for this carried a comment
            # reading "through haldir_tiers.limits(), not TIER_LIMITS.get()",
            # and a check that cannot tell prose from code would flag the
            # explanation of why not to do the thing as the thing itself.
            code = line.split("#", 1)[0]
            if re.search(r"(_DEFAULT_)?TIER_LIMITS\s*(\.get\(|\[)", code):
                offenders.append(f"{path}:{line_no}")
    assert not offenders, (
        f"these index the tier table directly, skipping the rename alias: "
        f"{offenders}. Call haldir_tiers.limits(tier) instead."
    )


def test_every_live_tier_has_a_rate_limit() -> None:
    """A tier missing from RATE_LIMITS does not fail, it silently throttles.

    The lookup is `RATE_LIMITS.get(tier, 100)` — free's ceiling. So when the
    paid plan was renamed to "usage", the new name was absent from the table
    while the retired "pro" stayed in it: the pricing page sold 5,000/hr and
    the middleware enforced 100/hr, a 50x reduction with nothing in the
    response to indicate it. The suite above could not catch this because
    RATE_LIMITS is a second table, and `test_no_caller_looks_up_a_tier_without_
    the_alias` only watches TIER_LIMITS.

    Compared against TIERS rather than a list written out here, so a plan
    added later cannot exist in one table and be missing from the other.
    """
    import api

    missing = [t for t in haldir_tiers.TIERS if t not in api.RATE_LIMITS]
    assert not missing, (
        f"these tiers have no rate limit, so they would fall back to free's "
        f"100/hr: {missing}. Add them to api.RATE_LIMITS."
    )

    # A retired name has to land on a live entry. Otherwise the alias maps it
    # to a tier that has no limit — the rename costs the tenant their ceiling
    # instead of preserving it, which is the failure the alias exists to stop.
    for old in haldir_tiers.RENAMED_TIERS:
        resolved = haldir_tiers.RENAMED_TIERS[old]
        assert resolved in api.RATE_LIMITS, (
            f"{old!r} resolves to {resolved!r}, which has no rate limit"
        )


def test_the_retired_name_is_not_stored_in_new_databases() -> None:
    """`haldir serve` must seed the tier's current name, not a retired one.

    Writing "pro" into a fresh database is how the name outlives the rename:
    every new local install then reports a plan that stopped existing, and the
    old name has to be kept working forever.
    """
    src = open(os.path.join(_ROOT, "cli.py"), encoding="utf-8").read()
    offenders = [
        f"cli.py:{n}"
        for n, line in enumerate(src.splitlines(), 1)
        if re.search(r'"local",\s*"pro"', line.split("#", 1)[0])
    ]
    assert not offenders, (
        f"these mint a key on the retired tier name: {offenders}. "
        f"Use {haldir_tiers.RENAMED_TIERS['pro']!r}."
    )


# ── Overage arithmetic ───────────────────────────────────────────────

def test_usage_is_billed_at_the_stated_rate() -> None:
    rate = haldir_tiers.TIERS["usage"]["overage_usd_per_action"]
    assert haldir_tiers.overage_cost("usage", 1_000_000) == round(1_000_000 * rate, 6)
    assert haldir_tiers.RATE_USD_PER_MILLION == round(rate * 1_000_000, 6)


def test_overage_is_none_rather_than_zero_when_uncapped() -> None:
    """None means 'not billable', and callers have to treat it that way.
    Returning 0.0 would read as 'free', which is a different thing."""
    assert haldir_tiers.overage_cost("free", 500) is None
    assert haldir_tiers.overage_cost("enterprise", 10**9) is None


def test_nothing_is_owed_for_usage_that_did_not_happen() -> None:
    assert haldir_tiers.overage_cost("usage", 0) is None
    assert haldir_tiers.overage_cost("usage", -5) is None


def test_idle_costs_nothing_and_one_call_costs_the_rate() -> None:
    """The property a usage price has to hold, now that no allowance stands
    in front of it: the first call is billable, and the bill is proportional.

    The retired model could not express this — every call below the allowance
    was free, so its test was about overage being *more* expensive than the
    included rate, or nobody would upgrade. With no subscription there is
    nothing to upgrade to, so that concern and its test are both gone.
    """
    rate = haldir_tiers.TIERS["usage"]["overage_usd_per_action"]
    assert haldir_tiers.overage_cost("usage", 1) == round(rate, 6)
    assert haldir_tiers.overage_cost("usage", 2) == round(rate * 2, 6)
    assert haldir_tiers.overage_cost("usage", 10**6) == round(rate * 10**6, 6)


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

    for name in ("free", "usage"):
        plan = haldir_tiers.limits(name)
        desc = offers.get(name, "")
        assert desc, f"landing page has no Offer for {name}"

        included = plan["actions_per_month"]
        if included is None:
            # No allowance to state, so the copy has to state the rate and
            # the absence of a fee — those are the whole offer.
            rate = f"${haldir_tiers.RATE_USD_PER_MILLION:,.0f} per million"
            assert rate in desc, (
                f"the landing page says '{desc}' for {name}, but the plan has "
                f"no allowance and a rate of {rate} calls"
            )
            assert "no monthly fee" in desc.lower(), (
                f"'{desc}' does not say the metered plan has no monthly fee. "
                f"That is the change the card exists to communicate — without "
                f"it the page still reads as a subscription."
            )
        else:
            assert f"{included:,}" in desc, (
                f"the landing page says '{desc}' for {name}, but the plan "
                f"allows {included:,} actions/month"
            )

        agents = plan["agents"]
        if agents < 999_999:
            assert (f"{agents} agents" in desc or f"{agents} agent" in desc
                    or "single agent" in desc), (
                f"the landing page does not state the {agents}-agent limit "
                f"for {name}: '{desc}'"
            )
        else:
            assert "unlimited agents" in desc.lower(), (
                f"the landing page does not say {name} has unlimited agents, "
                f"and the table sets no cap: '{desc}'"
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

    # Per million, not per month — there is no per-month number any more, and
    # a card that still carries one is describing the plan that was retired.
    rate = haldir_tiers.RATE_USD_PER_MILLION
    assert prices.get("usage") == f"{rate:,.0f}", (
        f"landing page prices Usage at ${prices.get('usage')} per million "
        f"but the table says ${rate:,.0f}"
    )
    assert prices.get("free") == "0", (
        f"landing page prices Free at ${prices.get('free')}"
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

    for name in ("free", "usage", "enterprise"):
        plan = haldir_tiers.limits(name)
        assert plan["label"] in html, f"/pricing renders no card for {name}"

    # The metered rate is that plan's entire price, and the card logic keys on
    # price_usd_month — which is 0 for usage and for free alike. Without a
    # branch for "no allowance" the page renders it as "$0 / forever", which
    # is the failure this assertion exists to catch.
    rate = haldir_tiers.RATE_USD_PER_MILLION
    assert f"${rate:,.0f}" in html, (
        f"/pricing does not state the ${rate:,.0f}-per-million rate. It is the "
        f"whole price of the metered plan, and a card without it reads as free."
    )
    assert "$0 <span>/ forever</span>" in html, (
        "/pricing no longer shows the free tier's price"
    )

    free = haldir_tiers.limits("free")
    assert f"{free['actions_per_month']:,}" in html, (
        "/pricing does not state Free's allowance"
    )

    # And the numbers it replaced are gone, not merely joined by the new ones.
    assert "$49" not in html, "/pricing still advertises the old $49"
    assert "$99" not in html, (
        "/pricing still advertises the retired $99/month subscription"
    )
    assert "50,000 actions" not in html, "/pricing still advertises the old allowance"
