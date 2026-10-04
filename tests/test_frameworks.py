"""The framework mappings: honest, complete, and pointing at real sections.

Adding regulatory clauses to an evidence document is the easiest place in this
codebase to do harm, because the failure mode is a customer believing they
have met an obligation they have not. So the tests here are less about
arithmetic and more about the four rules in `haldir_frameworks`'s docstring:

  * every clause says what it *contributes* and what it does **not** cover;
  * every clause names who the duty falls on — the EU AI Act's provider /
    deployer split is the one that gets collapsed by accident;
  * every section a clause references is a real evidence-pack section, so a
    typo cannot quietly point at nothing;
  * clauses nothing measures are reported unmeasured rather than scored.

Run: python -m pytest tests/test_frameworks.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
import haldir_compliance  # noqa: E402
import haldir_frameworks as fw  # noqa: E402

# The sections an evidence pack actually carries. Kept as a literal on purpose:
# deriving it from the pack would let a deleted section disappear from both
# sides at once, which is the drift this list exists to catch.
PACK_SECTIONS = {
    "identity", "access_control", "encryption", "audit_trail",
    "tamper_evidence", "spend_governance", "approvals", "webhooks",
    "agent_register",
}


@pytest.fixture(autouse=True)
def _release_rate_limit_budget():
    """These tests make real calls against the shared bootstrap key, and the
    suite's per-key hourly limiter counts them cumulatively. Without releasing
    the budget, modules that run later get 429s for reasons that have nothing
    to do with them — which is exactly what happened when this file was added.
    `fresh_counter` in conftest resets before a test; this releases after one,
    which is what a module adding load owes the rest of the suite.
    """
    yield
    import api  # imported here: not every module in this file needs it at import time
    api._rate_limits.clear()


# ── The mapping points at things that exist ────────────────────────────

def test_every_clause_references_real_pack_sections() -> None:
    """A clause whose `sections` name a section the pack does not have is a
    dangling reference — it reads as "see this evidence" and points at
    nothing. (This caught `proxy` and `alerting` while the mapping was being
    written; `alerting` is the *score* key for the `webhooks` section, and the
    two vocabularies are exactly how that slip happens.)"""
    for framework_id, framework in fw.FRAMEWORKS.items():
        for clause in framework["clauses"]:
            unknown = set(clause["sections"]) - PACK_SECTIONS
            assert not unknown, (
                f"{framework_id} {clause['clause']} references {sorted(unknown)}, "
                f"which are not evidence-pack sections"
            )
            assert clause["sections"], f"{clause['clause']} references no section at all"


def test_every_check_maps_to_a_clause_that_exists() -> None:
    """The reverse direction: a score check claiming relevance to a clause
    nobody wrote is a mapping to nowhere."""
    known = {
        framework_id: {c["clause"] for c in framework["clauses"]}
        for framework_id, framework in fw.FRAMEWORKS.items()
    }
    for check_key, mapping in fw.CHECK_CLAUSES.items():
        for framework_id, clauses in mapping.items():
            assert framework_id in fw.FRAMEWORKS, f"{check_key}: unknown framework {framework_id}"
            for clause in clauses:
                assert clause in known[framework_id], (
                    f"check {check_key!r} maps to {framework_id} {clause!r}, "
                    f"which no clause defines"
                )


# ── The honesty rules ──────────────────────────────────────────────────

def test_every_regulatory_clause_states_what_it_does_not_cover() -> None:
    """"Contributes to", never "satisfies". A clause with a contribution and
    no gap reads as a claim that the evidence closes it."""
    for framework_id in ("eu_ai_act", "iso_42001"):
        for clause in fw.FRAMEWORKS[framework_id]["clauses"]:
            assert clause["contribution"].strip(), f"{clause['clause']} has no contribution"
            assert clause.get("not_covered", "").strip(), (
                f"{framework_id} {clause['clause']} names no gap — every clause "
                f"here contributes to a criterion, none of them close one"
            )


def test_the_provider_deployer_split_is_preserved() -> None:
    """Article 12 is largely the *provider's* duty (build the system so it can
    log) and Article 26 the *deployer's* (keep the logs, monitor). Haldir's
    customer is usually the deployer. Collapsing the two tells a deployer they
    have met an obligation belonging to whoever built the model."""
    clauses = {c["clause"]: c for c in fw.FRAMEWORKS["eu_ai_act"]["clauses"]}
    assert clauses["Article 12(1)"]["applies_to"] == fw.PROVIDER
    assert clauses["Article 26(5)"]["applies_to"] == fw.DEPLOYER
    assert clauses["Article 26(6)"]["applies_to"] == fw.DEPLOYER
    for clause in clauses.values():
        assert clause["applies_to"] in {fw.PROVIDER, fw.DEPLOYER, fw.BOTH, "organisation"}


def test_the_six_month_floor_is_recorded() -> None:
    """Article 26(6)'s six months is the concrete number a deployer has to
    meet, and the retention machinery already exists to meet it. If this
    clause ever disappears from the mapping, that is a product decision
    someone should make on purpose."""
    clause = next(
        c for c in fw.FRAMEWORKS["eu_ai_act"]["clauses"] if c["clause"] == "Article 26(6)"
    )
    assert "six months" in clause["title"].lower()
    assert "retention" in clause["contribution"].lower()


# ── The report ─────────────────────────────────────────────────────────

def test_report_covers_all_three_frameworks_and_soc2_comes_from_the_pack() -> None:
    report = fw.framework_report(controls=haldir_compliance.SOC2_CONTROLS)
    assert set(report) == {"soc2", "eu_ai_act", "iso_42001"}
    soc2_clauses = {c["clause"] for c in report["soc2"]["clauses"]}
    assert soc2_clauses == {
        c["criterion"] for c in haldir_compliance.SOC2_CONTROLS.values()
    }, "SOC 2 clauses must be the pack's own control table, not a second copy"


def test_unmeasured_clauses_are_not_scored() -> None:
    """With no score supplied every clause is unmeasured — and unmeasured
    means no `state`, not a default one. A number invented for a clause
    Haldir cannot see is the overclaim this module exists to prevent."""
    report = fw.framework_report()
    for framework in report.values():
        for clause in framework["clauses"]:
            assert clause["measured"] is False
            assert "state" not in clause


def test_states_propagate_with_pass_strongest() -> None:
    """One clause, two checks, different states: the clause is as served as
    its best check. Averaging would let a clause with one failing and one
    passing check read as a gap it does not have."""
    score = {"criteria": [
        {"key": "audit_trail", "control": "CC7.2", "state": "pass"},
        {"key": "tamper_evidence", "control": "CC7.2", "state": "fail"},
    ]}
    report = fw.framework_report(controls=haldir_compliance.SOC2_CONTROLS, score=score)
    clause = next(
        c for c in report["eu_ai_act"]["clauses"] if c["clause"] == "Article 26(6)"
    )
    assert clause["measured"] is True
    assert clause["state"] == "pass", "pass must win over fail for the same clause"
    assert clause["checks"] == ["audit_trail", "tamper_evidence"]

    # And the reverse: only the failing one supplied.
    report = fw.framework_report(
        controls=haldir_compliance.SOC2_CONTROLS,
        score={"criteria": [{"key": "tamper_evidence", "control": "CC7.2", "state": "fail"}]},
    )
    clause = next(
        c for c in report["eu_ai_act"]["clauses"] if c["clause"] == "Article 26(6)"
    )
    assert clause["state"] == "fail"


# ── What the endpoints actually serve ──────────────────────────────────

def test_the_pack_carries_the_framework_mappings() -> None:
    pack = haldir_compliance.build_evidence_pack(api.DB_PATH, "framework-tenant")
    assert set(pack["frameworks"]) == {"soc2", "eu_ai_act", "iso_42001"}
    assert pack["frameworks"]["eu_ai_act"]["clauses"], "the AI Act mapping is empty"
    # The mapping is static, so two packs must agree — it is inside the
    # signed digest and must not move on its own.
    again = haldir_compliance.build_evidence_pack(api.DB_PATH, "framework-tenant")
    assert pack["frameworks"] == again["frameworks"]


def test_the_score_endpoint_groups_checks_by_framework() -> None:
    from haldir_compliance_score import compute_score

    score = compute_score(api.DB_PATH, "framework-tenant")
    frameworks = score["frameworks"]
    assert set(frameworks) == {"soc2", "eu_ai_act", "iso_42001"}

    by_clause = {c["clause"]: c for c in frameworks["eu_ai_act"]["clauses"]}
    # Every EU clause here is reachable from at least one check — if one
    # stopped being reachable, the score would silently stop answering for it.
    assert all(c["measured"] for c in by_clause.values())
    assert by_clause["Article 14"]["checks"] == ["approvals"]
    assert by_clause["Article 14"]["state"] in {"pass", "warn", "fail"}
