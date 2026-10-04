"""The frameworks this evidence is relevant to, stated plainly.

Three frameworks are mapped here — SOC 2 (via the control table in
`haldir_compliance`), the EU AI Act, and ISO/IEC 42001 — at the clause level,
each with what Haldir's evidence contributes and what it does not cover.

Four honesty rules, and they are the reason this file exists rather than a
list of clause numbers in a docstring:

1. **"Contributes to", never "satisfies".** An auditor decides satisfaction
   against the whole organisation. Every clause here names the gap as well as
   the contribution — the same shape `SOC2_CONTROLS` already uses.

2. **Who the duty falls on is recorded.** The EU AI Act separates *provider*
   obligations (build the system so it can log — Article 12) from *deployer*
   obligations (keep the logs, monitor the system — Article 26). Haldir's
   customer is usually the **deployer**. Collapsing the two would tell a
   deployer they have met an obligation that belongs to whoever built the
   model, which is exactly the mistake this field prevents.

3. **High-risk is a precondition, not a footnote.** Article 12 and Article 26
   duties attach to systems classified high-risk under Annex III. Haldir
   cannot classify someone's system, and a pack that implied it had would be
   giving legal advice it is not entitled to give.

4. **Nothing here is legal advice or a certification.** The same sentence the
   evidence pack carries: audit-prep, not an attestation.

Clause numbers were taken from the published regulation and from ISO/IEC
42001:2023's Annex A control list; where a control's exact placement is
disputed between public summaries (A.6.2.x has been miscatalogued by more than
one vendor), the mapping cites the ones confirmed across sources and leaves
the rest out rather than guessing.
"""

from __future__ import annotations

from typing import Any

# How a clause's duty is distributed. `both` is used only where the Act
# genuinely places the same duty on both roles.
PROVIDER = "provider"
DEPLOYER = "deployer"
BOTH = "provider + deployer"


FRAMEWORKS: dict[str, dict[str, Any]] = {
    "soc2": {
        "label": "SOC 2 (TSC 2017)",
        "note": (
            "Mapped per section in `haldir_compliance.SOC2_CONTROLS`, which "
            "the evidence pack has carried since it existed. Listed here so "
            "all three frameworks render from one place."
        ),
        "clauses": [],  # filled from SOC2_CONTROLS at report time
    },
    "eu_ai_act": {
        "label": "EU AI Act — Regulation (EU) 2024/1689",
        "note": (
            "Articles 12 and 26 attach to AI systems classified **high-risk** "
            "under Annex III. Haldir cannot classify a system, and does not "
            "try: this mapping says which evidence is relevant if yours is. "
            "Annex III obligations took effect 2 August 2026."
        ),
        "clauses": [
            {
                "clause": "Article 12(1)",
                "title": "Automatic recording of events over the system's lifetime",
                "applies_to": PROVIDER,
                "sections": ["audit_trail", "identity"],
                "contribution": (
                    "Every governed action is recorded automatically, at the "
                    "moment it happens, without an operator asking for it — "
                    "the three properties the clause turns on. Sessions carry "
                    "the acting agent's identity, and delegation is traced."
                ),
                "not_covered": (
                    "The duty is the provider's and covers the whole system; "
                    "Haldir records what passes through Haldir. Actions that "
                    "never touch it are not in the record."
                ),
            },
            {
                "clause": "Article 12(2)–(3)",
                "title": "Logs sufficient to identify risk situations and trace operation",
                "applies_to": PROVIDER,
                "sections": ["audit_trail", "agent_register", "webhooks"],
                "contribution": (
                    "The trail is queryable per session, agent, tool and "
                    "flagged status; flagged entries carry a reason; the "
                    "register shows which agent held which scopes and which "
                    "agents it spawned."
                ),
                "not_covered": (
                    "The Act does not prescribe fields, and this is not a "
                    "claim that our fields are the ones your risk assessment "
                    "needs. That mapping is yours to make."
                ),
            },
            {
                "clause": "Article 26(5)",
                "title": "Deployer monitors the system's operation",
                "applies_to": DEPLOYER,
                "sections": ["audit_trail", "webhooks", "spend_governance"],
                "contribution": (
                    "Monitoring is continuous rather than periodic: anomaly "
                    "flags on the entry, webhook alerting on notable events, "
                    "spend tracked per session and per agent."
                ),
                "not_covered": (
                    "Nothing here watches the model's outputs for accuracy or "
                    "bias. This is operational monitoring of what the agent "
                    "did, not evaluation of what the model said."
                ),
            },
            {
                "clause": "Article 26(6)",
                "title": "Deployer keeps automatically generated logs — at least six months",
                "applies_to": DEPLOYER,
                "sections": ["audit_trail", "tamper_evidence"],
                "contribution": (
                    "Entries are append-only and hash-chained, so a log "
                    "removed or edited later is detectable, and the retention "
                    "window is enforceable (`HALDIR_AUDIT_RETENTION_DAYS`). "
                    "Tamper-evidence matters to this clause specifically: a "
                    "log that can be silently altered is weak evidence that "
                    "the record is the record."
                ),
                "not_covered": (
                    "A six-month *minimum* is a floor, not a policy: whether "
                    "your sector requires longer, and whether the retention "
                    "window you configured satisfies it, is your call. "
                    "Retention is enforced against Haldir's own tables, not "
                    "against copies taken elsewhere."
                ),
            },
            {
                "clause": "Article 14",
                "title": "Human oversight",
                "applies_to": BOTH,
                "sections": ["approvals"],
                "contribution": (
                    "Approval rules park defined actions — by spend "
                    "threshold, by named tool — until a person decides, and "
                    "both the request and the decision are audited."
                ),
                "not_covered": (
                    "The Act's human-oversight duty goes further than "
                    "approval gates: it expects the oversight to be effective, "
                    "understood by the overseer, and able to interrupt the "
                    "system. Haldir provides the mechanism and the record; the "
                    "effectiveness is organisational."
                ),
            },
            {
                "clause": "Article 15",
                "title": "Accuracy, robustness and cybersecurity",
                "applies_to": PROVIDER,
                "sections": ["encryption", "access_control"],
                "contribution": (
                    "Credentials are encrypted at rest (AES-256-GCM), agents "
                    "hold scoped sessions rather than shared keys, and secrets "
                    "are released per request rather than handed to the model."
                ),
                "not_covered": (
                    "Model accuracy and adversarial robustness are not "
                    "measured here at all. This clause is largely the "
                    "provider's and largely about the model, not the runtime "
                    "around it."
                ),
            },
        ],
    },
    "iso_42001": {
        "label": "ISO/IEC 42001:2023 (AI management system)",
        "note": (
            "Annex A is a reference set an organisation selects from via its "
            "own risk assessment — not a checklist to complete. Only controls "
            "confirmed across published catalogues are cited; A.6.2.x in "
            "particular is miscatalogued by several vendors, and a wrong "
            "control number in an evidence pack is worse than a missing one."
        ),
        "clauses": [
            {
                "clause": "A.6.2.8",
                "title": "AI system recording of event logs",
                "applies_to": "organisation",
                "sections": ["audit_trail", "tamper_evidence", "agent_register"],
                "contribution": (
                    "The closest thing in Annex A to what Haldir is for: an "
                    "automatic, append-only record of what each AI system did, "
                    "per agent, with integrity that survives a skeptical "
                    "reviewer."
                ),
                "not_covered": (
                    "The control also expects the organisation to *define* "
                    "what gets logged. Haldir logs what passes through it; "
                    "your logging policy is the other half."
                ),
            },
            {
                "clause": "A.6.2.6",
                "title": "AI system operation and monitoring",
                "applies_to": "organisation",
                "sections": ["webhooks", "spend_governance", "audit_trail"],
                "contribution": (
                    "Operational monitoring with a response path: anomaly "
                    "flags, alerting webhooks with delivery accounting, and "
                    "spend caps that refuse the call rather than reporting it "
                    "afterwards."
                ),
                "not_covered": (
                    "Performance and model drift — the examples the control "
                    "gives — are not visible here. This monitors usage and "
                    "spend, not model quality."
                ),
            },
            {
                "clause": "A.6.2.4",
                "title": "AI system verification and validation",
                "applies_to": "organisation",
                "sections": ["tamper_evidence"],
                "contribution": (
                    "Independently verifiable records: RFC 6962 inclusion and "
                    "consistency proofs, Ed25519 Signed Tree Heads, and a "
                    "Sigstore Rekor mirror — verification an auditor can "
                    "perform offline, without trusting Haldir."
                ),
                "not_covered": (
                    "V&V of the AI system itself — does this model do what it "
                    "claims — is a different exercise and is not performed "
                    "here."
                ),
            },
            {
                "clause": "A.9.4",
                "title": "Intended use of the AI system",
                "applies_to": "organisation",
                "sections": ["access_control", "spend_governance"],
                "contribution": (
                    "Intended use is enforced technically rather than "
                    "documented only: scopes bound what an agent may reach, "
                    "spend caps bound what it may cost, and proxy mode refuses "
                    "tools outside policy."
                ),
                "not_covered": (
                    "The control expects a defined and documented intended "
                    "purpose per system. Haldir enforces the boundary you "
                    "configure; it does not decide where the boundary is."
                ),
            },
            {
                "clause": "A.9.2–A.9.3",
                "title": "Processes and objectives for responsible use",
                "applies_to": "organisation",
                "sections": ["approvals", "audit_trail"],
                "contribution": (
                    "Human-in-the-loop approvals for defined classes of "
                    "action, and a record of both the request and the decision "
                    "— the mechanism a responsible-use process needs to be "
                    "more than a policy document."
                ),
                "not_covered": (
                    "These are management-system controls about organisational "
                    "process. The pack evidences the technical half."
                ),
            },
        ],
    },
}


# Which score checks speak to which clauses, per framework. This is what lets
# the readiness score answer "how are we doing on the AI Act" without a second
# scoring engine or a second set of signals — the same checks, grouped.
#
# SOC 2 is deliberately absent: each check already carries its SOC 2 criterion
# (CriterionResult.control), and duplicating the mapping here is how two
# sources of truth start disagreeing.
CHECK_CLAUSES: dict[str, dict[str, tuple[str, ...]]] = {
    "access_control":   {"eu_ai_act": ("Article 15",), "iso_42001": ("A.9.4",)},
    "encryption":       {"eu_ai_act": ("Article 15",), "iso_42001": ()},
    "audit_trail":      {"eu_ai_act": ("Article 12(1)", "Article 12(2)–(3)",
                                       "Article 26(5)", "Article 26(6)"),
                         "iso_42001": ("A.6.2.8", "A.9.2–A.9.3")},
    "tamper_evidence":  {"eu_ai_act": ("Article 26(6)",),
                         "iso_42001": ("A.6.2.8", "A.6.2.4")},
    "alerting":         {"eu_ai_act": ("Article 12(2)–(3)", "Article 26(5)"),
                         "iso_42001": ("A.6.2.6",)},
    "spend_governance": {"eu_ai_act": ("Article 26(5)",), "iso_42001": ("A.6.2.6", "A.9.4")},
    "approvals":        {"eu_ai_act": ("Article 14",), "iso_42001": ("A.9.2–A.9.3",)},
}


def _framework_clauses(framework_id: str, controls: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The clause list for one framework. SOC 2's comes from the pack's own
    control table rather than a second copy."""
    if framework_id == "soc2":
        clauses = []
        for section, control in sorted((controls or {}).items()):
            clauses.append({
                "clause":      control.get("criterion", ""),
                "title":       control.get("title", ""),
                "sections":    [section],
                "contribution": control.get("evidence", ""),
                "not_covered": "",
            })
        return clauses
    return list(FRAMEWORKS[framework_id]["clauses"])


def framework_report(
    controls: dict[str, Any] | None = None,
    score: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The three frameworks, their clauses, and — when a score is supplied —
    which checks speak to each and what state they are in.

    A clause's state is the *best* state among its mapped checks, not the
    average: two checks can address one clause from different angles, and a
    clause served well by one of them is served. Clauses with no mapped check
    are reported `measured: false` rather than scored — most of the Act and
    most of Annex A is organisational, and a number invented for them would be
    exactly the overclaim this module exists to avoid.

    Note the two vocabularies: `sections` are evidence-pack section names,
    `checks` are readiness-score keys. "Alerting" in the score is the
    `webhooks` section in the pack; the fields keep each side's own name
    rather than forcing one to adopt the other's.
    """
    check_state: dict[str, str] = {}
    if score:
        for c in score.get("criteria", []):
            check_state[str(c.get("key", ""))] = str(c.get("state", ""))

    out: dict[str, Any] = {}
    for framework_id in ("soc2", "eu_ai_act", "iso_42001"):
        meta = FRAMEWORKS[framework_id]
        clauses: list[dict[str, Any]] = []
        for clause in _framework_clauses(framework_id, controls):
            mapped = sorted(
                key for key, mapping in CHECK_CLAUSES.items()
                if clause["clause"] in mapping.get(framework_id, ())
            )
            clause_states = [check_state[k] for k in mapped if k in check_state]
            entry: dict[str, Any] = {
                "clause":       clause["clause"],
                "title":        clause["title"],
                "sections":     clause["sections"],
                "contribution": clause["contribution"],
                "checks":       mapped,
                "measured":     bool(clause_states),
            }
            if clause["not_covered"]:
                entry["not_covered"] = clause["not_covered"]
            for state in ("pass", "warn", "fail"):
                if state in clause_states:
                    entry["state"] = state
                    break
            clauses.append(entry)
        out[framework_id] = {
            "label":    meta["label"],
            "note":     meta["note"],
            "clauses":  clauses,
            "measured": sum(1 for c in clauses if c["measured"]),
            "total":    len(clauses),
        }
    return out
