"""
Plan definitions — the single source of truth for what each tier gets.

This module exists because the numbers were written down in five places and
had drifted apart:

  * api.py            said Pro = 10 agents
  * haldir_admin.py   said Pro = 10 agents (a copy, "mirroring api.py")
  * landing/index.html said Pro = 25 agents, $99
  * api.py's pricing page said Pro = 10 agents, $49
  * the Stripe price was an env var, so a fifth answer lived in the deploy

So a customer could read "$99, 25 agents" on the marketing site and "$49,
10 agents" inside the product, and be capped at 10 either way. Nothing
caught it because nothing compared them — each copy was individually
plausible, and the only way to notice was to read all five.

Everything plan-related is defined here once, and every surface renders from
it, including the pricing page in the product. tests/test_tiers.py asserts
the marketing copy still agrees with this table, so the next drift fails a
test instead of reaching a customer.

## The usage model

Cloud and API are **pure usage billing**: one rate per API call to /v1/*, and
no subscription. Nothing recurs, there is nothing to upgrade to, and an
account that makes no calls owes nothing.

This replaced a $99/month plan with a 2.5M-call allowance and an overage
rate. That shape needed two numbers that had to agree with each other — the
allowance and the rate — plus an agent count the allowance had to be sized
against, and it had been got wrong three times. A single rate has one number
and no arithmetic to get wrong.

    RATE_USD_PER_CALL is $40 per million. That matches the effective rate the
    subscription charged at its own allowance ($99 / 2.5M = $39.60/M), so a
    customer using what the old plan included pays about what they paid
    before. It is deliberately below the old $100/M overage rate, which
    existed to make upgrading attractive; with nothing to upgrade to, that
    reason is gone and the number it justified is not.

Free is the exception and stays an allowance, because there is no card on
file to bill: 10,000 calls a month, hard-capped, one agent. The agent cap
survives on free alone — usage alone cannot express "do not run a fleet on
somebody else's unmetered allowance", since one runaway agent can burn the
whole allowance in hours.

Metering API calls rather than seats or agents is what lets the price express
the difference between a fleet doing nothing and a fleet doing work. One
consequence worth naming: the meter counts calls, including the ones that do
nothing, so a customer polling in a loop pays for the polling. That is the
normal shape of an API product and it is why the plan cards say "API calls"
rather than the vaguer "actions" the column is still named after.
"""

from __future__ import annotations

from typing import Any

# One unit is one authenticated API call to /v1/*, counted in api.py's
# track_usage after_request hook.
#
# The column and the plan key call it an "action", which is why this needs
# saying: an "action" here is not an audited operation. Five read-only
# GET /v1/audit calls meter as five units and write nothing to the audit
# chain. The name has already misled one reader of this file into describing
# the meter as counting audit entries, and the sizing arithmetic below was
# wrong because of it. The field name is kept for compatibility with the
# usage table and the API surface; the unit it holds is an API call.
METERED_UNIT = "API call"

# What one API call costs, in USD, on the metered plan.
#
# $0.00004 = $40 per million. Written as a per-call number because that is the
# unit the meter counts and the unit `overage_cost()` multiplies; the per-
# million figure is the one humans compare, so it is stated here and rendered
# on the pricing page rather than living only in someone's head.
#
# Kept equal to the effective rate the retired $99/2.5M plan charged
# ($39.60/M) so that moving to pure usage did not silently reprice anybody.
RATE_USD_PER_CALL = 0.00004
RATE_USD_PER_MILLION = RATE_USD_PER_CALL * 1_000_000

# Calls a free tenant gets each month before it is refused. Free has no card
# on file, so this is a ceiling rather than an allowance to bill past.
FREE_CALLS_PER_MONTH = 10_000

# Free is also the only plan with an agent cap — see the docstring.
FREE_AGENTS = 1

# ── Sizing assumptions ───────────────────────────────────────────────
#
# The allowances are derived from these rather than picked as round numbers,
# because a plan whose allowance cannot run the agents it advertises is a
# trap, and round numbers are exactly how that happens.
#
# One governed agent action — a tool call the proxy gates — costs more than
# one API call: the agent calls the proxy, and typically checks its session
# or reads something back. Two is the conservative figure; it is an
# assumption, not a measurement, and it is the number to change first if a
# real deployment shows otherwise.
API_CALLS_PER_AGENT_ACTION = 2

# One agent action per minute is a leisurely pace for an LLM agent, whose
# actions are bounded by model latency, not by the machine.
AGENT_ACTIONS_PER_MIN = 1

_MINUTES_PER_MONTH = 60 * 24 * 30


def api_calls_per_agent_per_month() -> int:
    """What one agent costs against the meter in a month.

    Single definition, because both the allowances below and the test that
    checks them need the same figure — and the last time this arithmetic was
    written down twice, the two copies disagreed.
    """
    return API_CALLS_PER_AGENT_ACTION * AGENT_ACTIONS_PER_MIN * _MINUTES_PER_MONTH


TIERS: dict[str, dict[str, Any]] = {
    "free": {
        "label": "Free",
        "agents": FREE_AGENTS,
        # ~7 days of continuous single-agent use. The old 1,000 was about
        # seventeen hours: too short to decide anything, and far too short to
        # produce the audit evidence the product is sold on — you cannot
        # evaluate a compliance tool on a workpaper it cannot fill.
        "actions_per_month": FREE_CALLS_PER_MONTH,
        "price_usd_month": 0,
        # No card on file, so no overage: the allowance is the allowance.
        "overage_usd_per_action": None,
        "hard_cap": True,
        "blurb": "Get started. One agent, full security.",
        "features": [
            "Session-scoped permissions",
            "Encrypted secret storage",
            "Audit trail",
            "MCP support",
            "Community support",
        ],
    },
    "usage": {
        "label": "Usage",
        # No agent limit. Agent count was a plan dimension when a plan had to
        # be sized to it; with one rate and no subscription there is nothing
        # for a cap to protect, and the customer is paying per call either
        # way. The free-tier cap is a separate thing — see the docstring.
        "agents": 999_999,
        # None, not 0: no calls are included, and 0 would render as an
        # allowance of zero on the card and as "remaining: 0" in the rate
        # limit headers — a limit that reads as already exceeded rather than
        # as one that does not exist.
        "actions_per_month": None,
        # Nothing recurs on any plan now. The key is kept because the pricing
        # page and the tests read it, and because deleting it would make
        # "does this recur?" a question about a missing key rather than a
        # stated zero.
        "price_usd_month": 0,
        "overage_usd_per_action": RATE_USD_PER_CALL,
        "hard_cap": False,
        "blurb": "Pay for what you call. No subscription, no minimum.",
        "features": [
            "Everything in Free",
            "No monthly fee — pay only for calls you make",
            "Unlimited agents",
            "Anomaly detection",
            "Webhooks (Slack, Discord)",
            "Human-in-the-loop approvals",
            "Proxy mode + governance policies",
            "Priority support",
        ],
    },
    "enterprise": {
        "label": "Enterprise",
        "agents": 999_999,
        "actions_per_month": 999_999_999,
        # Custom: negotiated, and usually on-prem, where metering does not
        # apply at all because the deployment is not ours to meter.
        "price_usd_month": None,
        "overage_usd_per_action": None,
        "hard_cap": False,
        "blurb": "Custom deployments, on-prem, and volume pricing.",
        "features": [
            "Everything in Pro",
            "Unlimited agents and actions",
            "On-prem / VPC deployment",
            "SSO and audit-log export",
            "Custom retention windows",
            "Support SLA",
        ],
    },
}


def feature_lines(tier: str) -> list[str]:
    """The bullet list for a plan's card, with usage rendered from the table.

    Generated rather than written out so the allowance on the card is the
    allowance the rate limiter enforces. The whole reason this module exists
    is that those two numbers were typed separately and disagreed.
    """
    plan = limits(tier)
    lines: list[str] = []
    agents = plan.get("agents", 0)
    lines.append(
        "Unlimited agents" if agents >= 999_999 else
        f"{agents} agent" if agents == 1 else
        f"{agents} agents"
    )
    included = plan.get("actions_per_month")
    rate = plan.get("overage_usd_per_action")
    if included is None:
        # Nothing is included, so there is nothing to be "beyond" — the rate
        # is the whole card, not an overage note under an allowance.
        if rate is not None:
            lines.append(
                f"${RATE_USD_PER_MILLION:,.0f} per million API calls"
            )
        lines.append("No monthly fee and no minimum — idle costs nothing")
    elif included >= 999_999_999:
        lines.append("Unlimited API calls / month")
    else:
        lines.append(f"{included:,} API calls / month included")
        if rate is not None:
            lines.append(
                f"${rate:,.4f} per API call beyond that, billed not blocked"
            )
    lines.extend(plan.get("features", []))
    return lines

# Free is the floor for anything unrecognised. An unknown tier string — a
# subscription row written by an older version, a typo in a Stripe price
# mapping — must not silently become Enterprise.
DEFAULT_TIER = "free"

# Plans that were renamed, pointing at what they are now.
#
# "pro" was a $99/month subscription. A `subscriptions` row written by that
# version still says "pro", and the fallback above would resolve it to free —
# dropping a paying tenant onto the 10,000-call hard cap mid-month. An alias
# rather than a duplicate entry, so there is one plan body and no second copy
# to drift.
RENAMED_TIERS = {"pro": "usage"}


def limits(tier: str, table: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """The plan dict for `tier`, falling back to free.

    `table` defaults to TIERS. It is a parameter because a caller may hold
    its own reference to the table — api.py's TIER_LIMITS, which nine test
    modules replace to lift the free-tier agent cap. Resolving through TIERS
    directly would walk straight past that replacement: the fixture would
    lift a cap nobody reads, and the suite would start 403-ing on "Agent
    limit reached" in files that never mentioned agents.
    """
    tbl = TIERS if table is None else table
    key = RENAMED_TIERS.get(tier or "", tier or DEFAULT_TIER)
    return tbl.get(key, tbl[DEFAULT_TIER])


def overage_cost(tier: str, actions_over: int) -> float | None:
    """What `actions_over` past the allowance costs on this plan.

    None when the plan has no overage rate — a free-plan tenant that
    exceeded its allowance, or an enterprise deployment that is not metered.
    Callers should treat None as "this usage is not billable", not as zero.
    """
    rate = limits(tier).get("overage_usd_per_action")
    if rate is None or actions_over <= 0:
        return None
    return round(float(rate) * actions_over, 6)


def is_hard_capped(tier: str) -> bool:
    """True when exceeding the allowance should be refused rather than
    billed. Only plans without a payment method behind them."""
    return bool(limits(tier).get("hard_cap", True))


def is_metered(tier: str) -> bool:
    """True when usage past the allowance is billed instead of refused."""
    return not is_hard_capped(tier) and limits(tier).get("overage_usd_per_action") is not None
