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

Cloud and API are usage-based: a monthly platform fee buys an allowance of
metered actions, and usage past the allowance is billed per action rather
than refused. The allowances are sized so that the agent count on a plan is
actually usable at it — which the previous numbers were not:

    Pro allowed 10 agents and 50,000 actions/month. One agent making a
    single tool call per minute — a leisurely pace, not a busy one — spends
    43,200 actions/month. That leaves 6,800 for the other nine agents. The
    plan could not run the fleet it advertised, and the ceiling would have
    been hit mid-task by an agent whose whole purpose is to be audited.

An action is one audited operation: a tool call, a payment, a secret access,
anything that writes to the audit chain. Metering that is a choice worth
naming — it is the thing the product exists to record, so a customer who
records less pays less, which is revenue pointed against the guarantee. The
mitigation is that overage is cheap and the tiers are generous enough that
nobody sane reaches for it; the alternative, metering seats or agents, cannot
express the difference between a fleet doing nothing and a fleet doing work.
"""

from __future__ import annotations

from typing import Any

# One audited operation is one unit. Named because "actions_per_month" is
# the field every caller reads and the unit deserves stating once.
METERED_UNIT = "action"

# Actions a single agent generates per month at one call per minute. Used to
# size the allowances below — kept here so the arithmetic that justifies the
# numbers is visible next to them rather than in someone's head.
_ACTIONS_PER_AGENT_AT_1_PER_MIN = 60 * 24 * 30  # 43,200


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
        # Sized to the agent count, with headroom: 25 agents x 43,200 =
        # 1,080,000, so the allowance has to clear that. This is the number
        # that makes the plan's own agent limit meaningful, and the first
        # draft of it was 1,000,000 — a rounder figure that was 80,000 short
        # and would have reintroduced the exact incoherence being fixed.
        # tests/test_tiers.py::test_a_paid_plan_can_run_the_agents_it_allows
        # is what caught it.
        "actions_per_month": 1_500_000,
        "price_usd_month": 99,
        # $200 per additional million — about 2x the effective included rate
        # of $99/1M, which is the usual shape for overage.
        "overage_usd_per_action": 0.0002,
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
        lines.append("Unlimited actions / month")
    else:
        lines.append(f"{included:,} actions / month included")
    rate = plan.get("overage_usd_per_action")
    if rate is not None:
        lines.append(f"${rate:,.4f} per action beyond that, billed not blocked")
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
    return round(actions_over * rate, 6)


def is_hard_capped(tier: str) -> bool:
    """True when exceeding the allowance should be refused rather than
    billed. Only plans without a payment method behind them."""
    return bool(limits(tier).get("hard_cap", True))


def is_metered(tier: str) -> bool:
    """True when usage past the allowance is billed instead of refused."""
    return not is_hard_capped(tier) and limits(tier).get("overage_usd_per_action") is not None
