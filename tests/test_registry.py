"""The agent register: every agent that has acted, from what was recorded.

The `agents` table has been written on every session creation since migration
001 and nothing has ever read it. These tests pin the properties the register
has to have to be worth reading at all:

  * an agent that acted but was never explicitly registered is still listed —
    a register that misses agents is worse than no register, because it reads
    as complete;
  * the numbers are the tenant's own (spend, actions, flags, approvals);
  * delegation is visible, because "which of my agents can spawn others" is
    the question the tree exists to answer;
  * another tenant's agents never appear.

Built on a throwaway SQLite file per test, through the Gate/Watch/Approvals
managers rather than HTTP — the HTTP layer enforces tier caps (`POST /v1/keys`
always mints a *free* key; only a payment webhook raises a tenant's tier), and
a test about the register should not be a test about the free tier's one-agent
limit.

Run: python -m pytest tests/test_registry.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_gate.approvals import ApprovalEngine  # noqa: E402
from haldir_gate.gate import Gate  # noqa: E402
from haldir_registry import build_register  # noqa: E402
from haldir_watch.watch import Watch  # noqa: E402

TENANT = "t-registry"


def _fixture(tmp_path, name: str):
    """A throwaway database with the base schema, then the managers on it.

    `init_db` is what the application calls at startup; the Gate, Watch and
    ApprovalEngine all assume those tables exist (Watch's anomaly rules among
    them) rather than creating them, so a bare file is not enough.
    """
    from haldir_db import init_db

    db = str(tmp_path / f"{name}.db")
    init_db(db)
    return db, Gate(db_path=db), Watch(db_path=db), ApprovalEngine(db_path=db)


def _agent_with_history(gate, watch, approvals, agent_id: str,
                        *, spend: float = 0.0, actions: int = 0,
                        cost_each: float = 0.0, approvals_pending: int = 0,
                        tenant: str = TENANT):
    """An agent, one session, N audit entries and optionally approvals."""
    gate.register_agent(agent_id, default_scopes=["read"], max_spend=100.0, tenant_id=tenant)
    session = gate.create_session(agent_id, scopes=["read"], ttl=3600,
                                  spend_limit=spend, tenant_id=tenant)
    for i in range(actions):
        watch.log_action(session, tool="tool", action=f"act{i}",
                         cost_usd=cost_each, tenant_id=tenant)
    for i in range(approvals_pending):
        approvals.request_approval(session, tool="stripe", action="charge",
                                   amount=10.0, reason=f"r{i}", tenant_id=tenant)
    return session


def test_an_agent_is_listed_with_its_policy_and_its_history(tmp_path) -> None:
    db, gate, watch, approvals = _fixture(tmp_path, "reg1")
    _agent_with_history(gate, watch, approvals, "research-bot",
                        spend=25.0, actions=3, cost_each=0.5, approvals_pending=1)

    out = build_register(db, TENANT)
    assert out["summary"]["agents"] == 1
    a = out["agents"][0]
    assert a["agent_id"] == "research-bot"
    assert a["registered"] is True
    assert a["default_scopes"] == ["read"]
    assert a["max_spend"] == 100.0
    assert a["sessions"]["total"] == 1
    assert a["sessions"]["active"] == 1
    assert a["spend"]["session_limits_usd"] == 25.0
    assert a["activity"]["actions"] == 3
    assert a["activity"]["cost_usd"] == 1.5
    assert a["approvals"] == {"requested": 1, "pending": 1}


def test_an_agent_that_acted_without_registering_is_still_listed(tmp_path) -> None:
    """The register is derived from activity as well as registration. An agent
    whose sessions exist but which never went through `register_agent` — an
    older row, a session minted straight through the Gate — must still appear,
    because a register that silently omits agents is worse than none."""
    db, gate, watch, _ = _fixture(tmp_path, "reg2")
    gate.create_session("ghost-agent", scopes=["read"], tenant_id=TENANT)

    out = build_register(db, TENANT)
    listed = {a["agent_id"]: a for a in out["agents"]}
    assert "ghost-agent" in listed
    assert listed["ghost-agent"]["registered"] is False
    assert listed["ghost-agent"]["sessions"]["total"] == 1
    assert out["summary"]["agents"] == 1


def test_delegation_is_visible_from_both_ends(tmp_path) -> None:
    """"Which of my agents can spawn others" is the question the delegation
    tree exists to answer, and it only has an answer if the register shows
    both directions."""
    db, gate, watch, _ = _fixture(tmp_path, "reg3")
    parent = gate.create_session("orchestrator", scopes=["read"], tenant_id=TENANT)
    gate.create_session("worker", scopes=["read"], tenant_id=TENANT,
                        parent_session_id=parent.session_id)

    by_id = {a["agent_id"]: a for a in build_register(db, TENANT)["agents"]}
    assert by_id["orchestrator"]["delegates_to"] == ["worker"]
    assert by_id["worker"]["spawned_by"] == ["orchestrator"]
    assert build_register(db, TENANT)["summary"]["delegation_edges"] == 1


def test_another_tenants_agents_never_appear(tmp_path) -> None:
    db, gate, watch, _ = _fixture(tmp_path, "reg4")
    _agent_with_history(gate, watch, _, "mine", tenant=TENANT)
    _agent_with_history(gate, watch, _, "theirs", tenant="t-somebody-else")

    out = build_register(db, TENANT)
    assert [a["agent_id"] for a in out["agents"]] == ["mine"]
    assert out["summary"]["agents"] == 1
    assert build_register(db, "t-somebody-else")["summary"]["agents"] == 1


def test_flagged_actions_roll_up_to_the_summary(tmp_path) -> None:
    db, gate, watch, _ = _fixture(tmp_path, "reg5")
    session = _agent_with_history(gate, watch, _, "risky", actions=2, cost_each=0.1)
    entry = watch.log_action(session, tool="shell", action="rm", tenant_id=TENANT)
    assert watch.flag_anomaly(entry.entry_id, "pattern", tenant_id=TENANT) is True

    out = build_register(db, TENANT)
    assert out["agents"][0]["activity"]["flagged"] == 1
    assert out["summary"]["flagged_actions"] == 1
    assert out["summary"]["agents_flagged"] == 1


def test_single_agent_lookup_and_an_absent_one(tmp_path) -> None:
    db, gate, watch, _ = _fixture(tmp_path, "reg6")
    _agent_with_history(gate, watch, _, "one")
    _agent_with_history(gate, watch, _, "two")

    one = build_register(db, TENANT, agent_id="one")
    assert [a["agent_id"] for a in one["agents"]] == ["one"]
    assert one["summary"]["agents"] == 1

    absent = build_register(db, TENANT, agent_id="nobody")
    assert absent["agents"] == []
    assert absent["summary"]["agents"] == 0


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


# ── The routes ────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _lift_agent_cap(monkeypatch) -> None:
    """Free tier caps agents at 1; the HTTP tests here need a few. The cap
    itself is covered by its own tests — this one is about the register."""
    import copy

    import api
    patched = copy.deepcopy(api.TIER_LIMITS)
    patched["free"]["agents"] = 999
    monkeypatch.setattr(api, "TIER_LIMITS", patched)


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def test_the_register_over_http(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post("/v1/sessions",
                           json={"agent_id": "http-agent", "scopes": ["read"]},
                           headers=_auth(bootstrap_key))
    assert r.status_code == 201, r.data

    body = haldir_client.get("/v1/agents", headers=_auth(bootstrap_key)).get_json()
    assert set(body) >= {"tenant_id", "generated_at", "summary", "agents"}
    listed = {a["agent_id"]: a for a in body["agents"]}
    assert "http-agent" in listed
    assert listed["http-agent"]["sessions"]["total"] == 1


def test_one_agent_and_an_absent_one_over_http(haldir_client, bootstrap_key) -> None:
    haldir_client.post("/v1/sessions", json={"agent_id": "solo", "scopes": ["read"]},
                       headers=_auth(bootstrap_key))

    one = haldir_client.get("/v1/agents/solo", headers=_auth(bootstrap_key))
    assert one.status_code == 200
    assert one.get_json()["agent_id"] == "solo"

    missing = haldir_client.get("/v1/agents/nobody", headers=_auth(bootstrap_key))
    assert missing.status_code == 404
    assert missing.get_json()["code"] == "not_found"


def test_the_register_needs_a_key(haldir_client) -> None:
    assert haldir_client.get("/v1/agents").status_code == 401
    assert haldir_client.get("/v1/agents/anyone").status_code == 401
