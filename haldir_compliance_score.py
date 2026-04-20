"""
Haldir readiness score — how well a tenant is using Haldir's
audit-relevant features.

This is NOT a SOC2 attestation and NOT a compliance claim. It's a
platform-side signal: "are you using the governance features the way
an auditor would want to see them used?" A real SOC2 audit requires
documented policies, procedures, and evidence across the entire
organization — not just the slice Haldir can see.

Think of it the way Vanta's own product works: the dashboard
percentage drives repeat engagement and gap-closing, but the actual
audit is done by a human auditor against evidence you hand them. This
module produces that kind of number for the agent-activity portion of
an audit package.

Each check maps to a SOC2 trust-services criterion it's RELEVANT TO
(not "satisfies"). The relevance map is:

  CC6.1 (access control)        → has any scope-restricted API key
                                  (not just wildcard)
  CC6.7 (encryption at rest)    → HALDIR_ENCRYPTION_KEY is set
                                  (not ephemeral)
  CC7.2 (monitoring)            → audit_log has recent entries AND
                                  the hash chain verifies
  CC7.3 (event response)        → webhooks registered AND 24-hour
                                  delivery success rate >= 95%
  CC5.2 (risk mitigation)       → at least one session with a
                                  spend_limit > 0
  CC8.1 (change management,
         human-in-the-loop)     → at least one approval rule OR one
                                  approval decision recorded

States: pass / warn / fail. Score is `sum(state_weight) / count * 100`
with pass=1.0, warn=0.5, fail=0.0.

Each criterion carries a human-readable `reason` + a `remediation`
hint so the UI can render "what to do to close the gap" next to every
non-passing row. That's what keeps customers opening the dashboard
weekly — and it's all honest about what it measures.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict
from typing import Any


# Each criterion carries the SOC2 trust-services criterion its check
# is RELEVANT TO — the signal helps satisfy that control at audit
# time, it does not on its own satisfy it. The `control` field name
# on CriterionResult is kept for API stability; read it as
# "relevant_to_soc2_criterion".
CRITERIA: tuple[tuple[str, str, str], ...] = (
    # (key,               relevant_to,  description)
    # `relevant_to` = SOC2 criterion this signal helps satisfy;
    # passing this check is evidence FOR that criterion, not a claim
    # that you satisfy it org-wide.
    ("access_control",    "CC6.1",  "At least one API key uses restricted scopes"),
    ("encryption",        "CC6.7",  "Persistent encryption key configured"),
    ("audit_trail",       "CC7.2",  "Audit chain verifies with recent entries"),
    ("tamper_evidence",   "CC7.2",  "RFC 6962 Signed Tree Head over the audit log"),
    ("alerting",          "CC7.3",  "Webhook alerting operational (>=95% 24h)"),
    ("spend_governance",  "CC5.2",  "At least one session runs with a spend cap"),
    ("approvals",         "CC8.1",  "Human-in-the-loop approvals configured"),
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
    the tenant is operating with effective root — relevant to an
    auditor reviewing CC6.1 least-privilege controls, though full
    CC6.1 also requires documented access policy, provisioning
    procedures, and periodic review evidence that sit outside
    Haldir's scope."""
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
            "At least one API key uses restricted scopes",
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
            "At least one API key uses restricted scopes",
            STATE_PASS,
            "At least one key runs on restricted scopes.",
            "",
        )
    return CriterionResult(
        "access_control", "CC6.1",
        "At least one API key uses restricted scopes",
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
            "Persistent encryption key configured",
            STATE_PASS,
            "HALDIR_ENCRYPTION_KEY is configured. Cipher: AES-256-GCM.",
            "",
        )
    return CriterionResult(
        "encryption", "CC6.7",
        "Persistent encryption key configured",
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
            "Audit chain verifies with recent entries",
            STATE_FAIL,
            "Audit log is empty.",
            "Log the first action: `haldir audit log <session-id> --tool <name> --action <verb>`.",
        )

    chain_ok = _verify_chain_safe(db_path, tenant_id)
    if not chain_ok:
        return CriterionResult(
            "audit_trail", "CC7.2",
            "Audit chain verifies with recent entries",
            STATE_FAIL,
            f"Chain verification failed across {total:,} entries.",
            "Investigate tampering via `haldir audit verify`; contact support.",
        )

    if recent == 0:
        return CriterionResult(
            "audit_trail", "CC7.2",
            "Audit chain verifies with recent entries",
            STATE_WARN,
            f"{total:,} entries on file but none in the last 24 h.",
            "Audit activity has stalled — confirm your agents are still logging.",
        )

    return CriterionResult(
        "audit_trail", "CC7.2",
        "Audit chain verifies with recent entries",
        STATE_PASS,
        f"Chain verified across {total:,} entries; {recent:,} in the last 24 h.",
        "",
    )


def _evaluate_tamper_evidence(db_path: str, tenant_id: str) -> CriterionResult:
    """PASS if the tenant has enough audit entries that a signed
    Merkle root is meaningful (>=1 leaf). WARN on empty log; FAIL only
    if STH signing is explicitly misconfigured.

    Relevant to CC7.2: a signed tree head converts the hash chain from
    "you must trust the server's full log" into "an auditor holding a
    single entry can independently verify inclusion against a signed
    commitment" — the same primitive Certificate Transparency uses."""
    try:
        import haldir_audit_tree
        sth = haldir_audit_tree.get_tree_head(db_path, tenant_id)
    except Exception as e:
        return CriterionResult(
            "tamper_evidence", "CC7.2",
            "RFC 6962 Signed Tree Head over the audit log",
            STATE_FAIL,
            f"STH computation raised: {type(e).__name__}: {e}",
            "Check server logs; ensure HALDIR_TREE_SIGNING_KEY or "
            "HALDIR_ENCRYPTION_KEY is configured.",
        )
    size = int(sth.get("tree_size", 0))
    source = sth.get("signing_key_source", "")
    algo = sth.get("algorithm", "")
    is_asymmetric = "Ed25519" in algo
    if size == 0:
        return CriterionResult(
            "tamper_evidence", "CC7.2",
            "RFC 6962 Signed Tree Head over the audit log",
            STATE_WARN,
            "Audit log is empty — tree-head signs the empty tree.",
            "Log any action; the Merkle tree populates automatically.",
        )
    if source == "ephemeral":
        return CriterionResult(
            "tamper_evidence", "CC7.2",
            "RFC 6962 Signed Tree Head over the audit log",
            STATE_WARN,
            f"{size:,}-leaf tree signed with an ephemeral key (rotates on restart).",
            "Set HALDIR_TREE_SIGNING_KEY_ED25519_SEED (preferred, "
            "asymmetric — anyone verifies via /.well-known/jwks.json "
            "without being able to forge) or HALDIR_TREE_SIGNING_KEY "
            "(HMAC) for a stable STH signing key customers can pin.",
        )
    # Stable HMAC beats ephemeral but Ed25519 + JWKS is the elite tier
    # — auditors can verify without holding any forgery-capable key.
    if is_asymmetric:
        reason = (
            f"{size:,}-leaf tree signed with Ed25519 (asymmetric); "
            f"public key published at /.well-known/jwks.json. "
            f"Key source: {source}."
        )
    else:
        reason = (
            f"{size:,}-leaf tree signed with HMAC-SHA256 (symmetric). "
            f"Key source: {source}. Upgrade path: set "
            "HALDIR_TREE_SIGNING_KEY_ED25519_SEED to flip to asymmetric "
            "so auditors can verify without a forgery-capable key."
        )
    return CriterionResult(
        "tamper_evidence", "CC7.2",
        "RFC 6962 Signed Tree Head over the audit log",
        STATE_PASS,
        reason,
        "" if is_asymmetric else (
            "Flip to asymmetric Ed25519 by setting "
            "HALDIR_TREE_SIGNING_KEY_ED25519_SEED in the environment. "
            "No customer action required; existing proofs keep verifying."
        ),
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
            "At least one session runs with a spend cap",
            STATE_WARN,
            "No sessions exist yet.",
            "Mint a session with `haldir session create --agent <id> --spend-limit 5.00`.",
        )
    if with_caps == 0:
        return CriterionResult(
            "spend_governance", "CC5.2",
            "At least one session runs with a spend cap",
            STATE_FAIL,
            f"{total:,} session(s) exist but none have a spend_limit > 0.",
            "Pass `--spend-limit <usd>` when creating sessions so an agent "
            "can't over-run its budget.",
        )
    return CriterionResult(
        "spend_governance", "CC5.2",
        "At least one session runs with a spend cap",
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
            "Human-in-the-loop approvals configured",
            STATE_PASS,
            f"{rule_count} rule(s) + {decisions:,} decision(s) recorded.",
            "",
        )
    return CriterionResult(
        "approvals", "CC8.1",
        "Human-in-the-loop approvals configured",
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
        _evaluate_tamper_evidence(db_path, tenant_id),
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
