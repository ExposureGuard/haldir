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

Cloud and API are usage-based on **API calls to /v1/***. A monthly platform
fee buys an allowance of those calls, and usage past the allowance is billed
rather than refused. The allowances are sized so the agent count on a plan is
actually usable at it, which the previous numbers were not:

    Pro allowed 10 agents and 50,000 API calls/month. One agent costs 86,400
    of them (see the assumptions below), so the plan ran out less than
    two-thirds of the way through a single agent's month — while advertising
    ten. The ceiling would have been hit mid-task by an agent whose whole
    purpose is to be audited.

Metering API calls rather than seats or agents is what lets a plan express
the difference between a fleet doing nothing and a fleet doing work. It has
one consequence worth naming: the meter counts calls, including the ones that
do nothing, so a customer polling in a loop pays for the polling. That is the
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
        "agents": 1,
        # ~7 days of continuous single-agent use. The old 1,000 was about
        # seventeen hours: too short to decide anything, and far too short to
        # produce the audit evidence the product is sold on — you cannot
        # evaluate a compliance tool on a workpaper it cannot fill.
        "actions_per_month": 10_000,
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
    "pro": {
        "label": "Pro",
        "agents": 25,
        # Sized to the agent count, with headroom: 25 agents x 86,400 =
        # 2,160,000, so the allowance has to clear that. This is the number
        # that makes the plan's own agent limit meaningful, and it has been
        # wrong twice — first 50,000 (a tenth of one agent), then 1,000,000
        # (a rounder figure 80,000 short), then 1,500,000 sized against a
        # unit that was not the one being metered. Each time the arithmetic
        # test caught it, which is the reason that test exists.
        "actions_per_month": 2_500_000,
        "price_usd_month": 99,
        # $100 per additional million, about 2.5x the effective included rate
        # of $99/2.5M — the usual shape for overage. It has to stay above the
        # included rate or nobody would ever upgrade; they would just run
        # past the cap.
        "overage_usd_per_action": 0.0001,
        "hard_cap": False,
        "blurb": "For teams running multiple agents in production.",
        "features": [
            "Everything in Free",
            "Usage-based: overage billed, never blocked",
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
    included = plan.get("actions_per_month", 0)
    if included >= 999_999_999:
        lines.append("Unlimited API calls / month")
    else:
        lines.append(f"{included:,} API calls / month included")
    rate = plan.get("overage_usd_per_action")
    if rate is not None:
        lines.append(f"${rate:,.4f} per API call beyond that, billed not blocked")
    lines.extend(plan.get("features", []))
    return lines

# Free is the floor for anything unrecognised. An unknown tier string — a
# subscription row written by an older version, a typo in a Stripe price
# mapping — must not silently become Enterprise.
DEFAULT_TIER = "free"


def limits(tier: str) -> dict[str, Any]:
    """The plan dict for `tier`, falling back to free."""
    return TIERS.get(tier or DEFAULT_TIER, TIERS[DEFAULT_TIER])


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
