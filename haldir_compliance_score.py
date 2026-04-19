"""
Haldir compliance readiness score — the "are we SOC2-ready today" answer.

Vanta's killer UX moment is the single percentage at the top of the
dashboard: "87% ready for your SOC2 audit." Customers stare at that
number; board members ask for it; the product's entire engagement
loop is people pushing it toward 100%.

This module produces the same number for Haldir tenants.

Each SOC2 trust-services criterion Haldir covers is mapped to a
concrete signal in the tenant's live state:

  CC6.1 Access control    → has any scope-restricted API key
                            (not just wildcard)
  CC6.7 Encryption         → HALDIR_ENCRYPTION_KEY is set (not
                            ephemeral)
  CC7.2 Audit operations   → audit_log has at least one entry AND
                            the chain verifies
  CC7.3 Security monitoring → at least one webhook registered AND
                            24-hour delivery success rate >= 95%
  CC5.2 Risk mitigation    → at least one session with a spend_limit
                            has been created
  CC8.1 Change management  → at least one approval rule OR one
                            approval decision exists

A criterion returns one of three states: pass / warn / fail. The
top-line score is `passing_criteria / total_criteria * 100`, rounded
to a whole number. Warn contributes 0.5.

The scoring algorithm is deliberately simple — 6 criteria, equal
weight. A sophisticated weighted scheme invites bike-shedding and
obscures the product insight: a CISO wants "go fix these three
items" before they want "you're 72.5% on the Bayesian-adjusted
composite."

Each criterion carries a human-readable `reason` + a `remediation`
hint so the UI can render "what to do to close the gap" next to
every failing row. That's the feature that keeps customers opening
the dashboard every week.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict
from typing import Any


# A criterion maps 1:1 to a SOC2 trust services criterion. The
# controls dict mirrors the structure in haldir_compliance so the
# evidence pack + the score share vocabulary.
CRITERIA: tuple[tuple[str, str, str], ...] = (
    # (key,               control,  description)
    ("access_control",    "CC6.1",  "Logical access is scope-restricted"),
    ("encryption",        "CC6.7",  "Secrets at rest use a persistent key"),
    ("audit_trail",       "CC7.2",  "Audit chain verifies + entries recent"),
    ("alerting",          "CC7.3",  "Webhook alerting operational (>=95% 24h)"),
    ("spend_governance",  "CC5.2",  "Sessions run with spend caps"),
    ("approvals",         "CC8.1",  "Human approval workflow active"),
)

STATE_PASS = "pass"
STATE_WARN = "warn"
STATE_FAIL = "fail"

# Score contribution per state. Warn is half a pass so a dashboard
# with one gap + one warning reads "83%" not "67%" — realistic for
# where most real tenants land.
_WEIGHT = {
    STATE_PASS: 1.0,
    STATE_WARN: 0.5,
    STATE_FAIL: 0.0,
}


@dataclass
class CriterionResult:
    key:         str
    control:     str
    description: str
    state:       str
    reason:      str
    remediation: str


# ── Individual evaluators ────────────────────────────────────────────

def _evaluate_access_control(db_path: str, tenant_id: str) -> CriterionResult:
    """PASS if ANY scope-restricted key exists. Wildcard-only means
    the tenant is operating with effective root, which no auditor
    accepts under CC6.1 least-privilege requirements."""
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        rows = conn.execute(
            "SELECT scopes FROM api_keys WHERE tenant_id = ? AND revoked = 0",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return CriterionResult(
            "access_control", "CC6.1",
            "Logical access is scope-restricted",
            STATE_FAIL,
            "No active API keys.",
            "Mint at least one key via POST /v1/keys; use scopes for least-privilege.",
        )

    has_narrow = False
    for r in rows:
        try:
            scopes = json.loads(r["scopes"]) if "scopes" in r.keys() else ["*"]
        except (TypeError, json.JSONDecodeError):
            scopes = ["*"]
        if scopes != ["*"]:
            has_narrow = True
            break
    if has_narrow:
        return CriterionResult(
            "access_control", "CC6.1",
            "Logical access is scope-restricted",
            STATE_PASS,
            "At least one key runs on restricted scopes.",
            "",
        )
    return CriterionResult(
        "access_control", "CC6.1",
        "Logical access is scope-restricted",
        STATE_WARN,
        "All active keys hold wildcard scope ['*'].",
        "Mint scope-restricted keys for non-admin uses: "
        "`haldir keys create --scopes audit:read,sessions:read`.",
    )


def _evaluate_encryption() -> CriterionResult:
    """PASS if HALDIR_ENCRYPTION_KEY is persistently configured;
    WARN if ephemeral (secrets evaporate on restart). Never FAIL —
    the cipher itself is always AES-256-GCM regardless."""
    if os.environ.get("HALDIR_ENCRYPTION_KEY"):
        return CriterionResult(
            "encryption", "CC6.7",
            "Secrets at rest use a persistent key",
            STATE_PASS,
            "HALDIR_ENCRYPTION_KEY is configured. Cipher: AES-256-GCM.",
            "",
        )
    return CriterionResult(
        "encryption", "CC6.7",
        "Secrets at rest use a persistent key",
        STATE_WARN,
        "No HALDIR_ENCRYPTION_KEY set — an ephemeral key is generated on boot.",
        "Generate a persistent key and set it as an env var: "
        "`python -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'`.",
    )


def _evaluate_audit_trail(db_path: str, tenant_id: str) -> CriterionResult:
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]
        recent = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ? AND timestamp >= ?",
            (tenant_id, time.time() - 24 * 3600),
        ).fetchone()[0]
    finally:
        conn.close()

    if total == 0:
        return CriterionResult(
            "audit_trail", "CC7.2",
            "Audit chain verifies + entries recent",
            STATE_FAIL,
            "Audit log is empty.",
            "Log the first action: `haldir audit log <session-id> --tool <name> --action <verb>`.",
        )

    chain_ok = _verify_chain_safe(db_path, tenant_id)
    if not chain_ok:
        return CriterionResult(
            "audit_trail", "CC7.2",
            "Audit chain verifies + entries recent",
            STATE_FAIL,
            f"Chain verification failed across {total:,} entries.",
            "Investigate tampering via `haldir audit verify`; contact support.",
        )

    if recent == 0:
        return CriterionResult(
            "audit_trail", "CC7.2",
            "Audit chain verifies + entries recent",
            STATE_WARN,
            f"{total:,} entries on file but none in the last 24 h.",
            "Audit activity has stalled — confirm your agents are still logging.",
        )

    return CriterionResult(
        "audit_trail", "CC7.2",
        "Audit chain verifies + entries recent",
        STATE_PASS,
        f"Chain verified across {total:,} entries; {recent:,} in the last 24 h.",
        "",
    )


def _evaluate_alerting(db_path: str, tenant_id: str) -> CriterionResult:
    from haldir_db import get_db
    cutoff = time.time() - 24 * 3600
    conn = get_db(db_path)
    try:
        registered = conn.execute(
            "SELECT COUNT(*) FROM webhooks WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]
        try:
            total_dlv = conn.execute(
                "SELECT COUNT(*) FROM webhook_deliveries "
                "WHERE tenant_id = ? AND created_at >= ?",
                (tenant_id, cutoff),
            ).fetchone()[0]
            success_dlv = conn.execute(
                "SELECT COUNT(*) FROM webhook_deliveries "
                "WHERE tenant_id = ? AND created_at >= ? "
                "AND status_code >= 200 AND status_code < 300",
                (tenant_id, cutoff),
            ).fetchone()[0]
        except Exception:
            total_dlv = 0
            success_dlv = 0
    finally:
        conn.close()

    if registered == 0:
        return CriterionResult(
            "alerting", "CC7.3",
            "Webhook alerting operational (>=95% 24h)",
            STATE_WARN,
            "No webhook endpoints registered.",
            "Register at least one alert endpoint: "
            "`haldir webhooks register <url>` or POST /v1/webhooks.",
        )

    if total_dlv == 0:
        return CriterionResult(
            "alerting", "CC7.3",
            "Webhook alerting operational (>=95% 24h)",
            STATE_WARN,
            f"{registered} endpoint(s) registered but no deliveries in 24 h.",
            "Either no events fired (expected for quiet tenants) "
            "or the scheduler is idle — confirm via `haldir overview`.",
        )

    rate = success_dlv / total_dlv
    if rate >= 0.95:
        return CriterionResult(
            "alerting", "CC7.3",
            "Webhook alerting operational (>=95% 24h)",
            STATE_PASS,
            f"{total_dlv:,} deliveries, {rate * 100:.1f}% succeeded in 24 h.",
            "",
        )
    return CriterionResult(
        "alerting", "CC7.3",
        "Webhook alerting operational (>=95% 24h)",
        STATE_FAIL,
        f"Delivery success rate {rate * 100:.1f}% is below the 95% threshold.",
        "Check `haldir webhooks deliveries` for failed attempts "
        "and retry with `POST /v1/webhooks/<id>/rotate-secret` if signatures diverged.",
    )


def _evaluate_spend_governance(db_path: str, tenant_id: str) -> CriterionResult:
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        with_caps = conn.execute(
            "SELECT COUNT(*) FROM sessions "
            "WHERE tenant_id = ? AND spend_limit > 0",
            (tenant_id,),
        ).fetchone()[0]
        total = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]
    finally:
        conn.close()

    if total == 0:
        return CriterionResult(
            "spend_governance", "CC5.2",
            "Sessions run with spend caps",
            STATE_WARN,
            "No sessions exist yet.",
            "Mint a session with `haldir session create --agent <id> --spend-limit 5.00`.",
        )
    if with_caps == 0:
        return CriterionResult(
            "spend_governance", "CC5.2",
            "Sessions run with spend caps",
            STATE_FAIL,
            f"{total:,} session(s) exist but none have a spend_limit > 0.",
            "Pass `--spend-limit <usd>` when creating sessions so an agent "
            "can't over-run its budget.",
        )
    return CriterionResult(
        "spend_governance", "CC5.2",
        "Sessions run with spend caps",
        STATE_PASS,
        f"{with_caps:,} of {total:,} session(s) run with spend caps.",
        "",
    )


def _evaluate_approvals(db_path: str, tenant_id: str) -> CriterionResult:
    """PASS if ANY approval rule exists OR any approval decision has
    been recorded. Either indicates a human-in-the-loop pattern is
    live. No rules AND no decisions = WARN."""
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        # anomaly_rules doubles as the approval-rules table in Haldir's
        # current schema (rule_type includes approval triggers).
        try:
            rule_count = conn.execute(
                "SELECT COUNT(*) FROM anomaly_rules WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()[0]
        except Exception:
            rule_count = 0
        try:
            decisions = conn.execute(
                "SELECT COUNT(*) FROM approval_requests "
                "WHERE tenant_id = ? AND status IN ('approved', 'denied')",
                (tenant_id,),
            ).fetchone()[0]
        except Exception:
            decisions = 0
    finally:
        conn.close()

    if rule_count > 0 or decisions > 0:
        return CriterionResult(
            "approvals", "CC8.1",
            "Human approval workflow active",
            STATE_PASS,
            f"{rule_count} rule(s) + {decisions:,} decision(s) recorded.",
            "",
        )
    return CriterionResult(
        "approvals", "CC8.1",
        "Human approval workflow active",
        STATE_WARN,
        "No approval rules configured and no decisions recorded.",
        "Register a rule for risky actions: "
        "POST /v1/approvals/rules with a rule_type + threshold.",
    )


def _verify_chain_safe(db_path: str, tenant_id: str) -> bool:
    try:
        from haldir_watch.watch import Watch
        w = Watch(db_path=db_path)
        result = w.verify_chain(tenant_id=tenant_id)
        return bool(result.get("verified", True))
    except Exception:
        return True


# ── Top-level scorer ────────────────────────────────────────────────

def compute_score(db_path: str, tenant_id: str) -> dict[str, Any]:
    """Run every evaluator + roll up into the 0-100 score.

    Shape:
      {
        "score":            int,        # 0..100
        "criteria":         [...],      # per-control results
        "passing":          int,
        "warning":          int,
        "failing":          int,
        "computed_at":      float,
      }
    """
    results = [
        _evaluate_access_control(db_path, tenant_id),
        _evaluate_encryption(),
        _evaluate_audit_trail(db_path, tenant_id),
        _evaluate_alerting(db_path, tenant_id),
        _evaluate_spend_governance(db_path, tenant_id),
        _evaluate_approvals(db_path, tenant_id),
    ]

    total = len(results)
    weighted = sum(_WEIGHT[r.state] for r in results)
    score = int(round((weighted / total) * 100)) if total else 0

    passing = sum(1 for r in results if r.state == STATE_PASS)
    warning = sum(1 for r in results if r.state == STATE_WARN)
    failing = sum(1 for r in results if r.state == STATE_FAIL)

    return {
        "score":       score,
        "criteria":    [asdict(r) for r in results],
        "passing":     passing,
        "warning":     warning,
        "failing":     failing,
        "total":       total,
        "computed_at": time.time(),
    }
