"""The dashboard reads fields the API actually returns.

The cloud dashboard's JavaScript (`dashboard.js`, the page served at
`/cloud/overview`) is written by hand against payloads produced elsewhere, and
nothing compared the two — so a rename on either side emptied a column
silently. These tests parse the real template and resolve every field it reads
against a real row from the endpoint it calls.

This file currently covers the **agents** page. `fix/dashboard-webhooks` adds
the same helpers plus the webhooks, approvals and compliance pages; whichever
of the two lands second should keep both sets (they are additive — the helpers
are identical).

Run: python -m pytest tests/test_dashboard_contract.py -v
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_DASHBOARD_JS = (Path(__file__).resolve().parent.parent / "dashboard.js").read_text(
    encoding="utf-8"
)


def _body_of(function_name: str) -> str:
    """The source of one loader, from its `function` line to the next one."""
    start = _DASHBOARD_JS.index("function " + function_name)
    end = _DASHBOARD_JS.find("\n  function ", start + 1)
    return _DASHBOARD_JS[start:end if end != -1 else len(_DASHBOARD_JS)]


def _fields_read(block: str, variable: str) -> set[str]:
    """`variable.field` accesses in a template. Word-boundary anchored so
    `window.location` cannot be read as `w.location`."""
    return set(re.findall(rf"\b{re.escape(variable)}\.([a-zA-Z_]+)", block))


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture(autouse=True)
def _allow_unresolvable_test_urls(monkeypatch):
    monkeypatch.setenv("HALDIR_ALLOW_PRIVATE_WEBHOOKS", "1")


def test_the_agents_table_reads_fields_the_register_returns(
    haldir_client, bootstrap_key
) -> None:
    """The register page reads GET /v1/agents, whose field names come from
    `haldir_registry`. What the template reads must exist in the payload,
    checked against a real row rather than against a copy of the names."""
    import api

    tenant = haldir_client.get(
        "/v1/admin/overview", headers=_auth(bootstrap_key)
    ).get_json()["tenant_id"]
    # Through the Gate, not POST /v1/sessions: that route enforces the tier's
    # agent cap, and a full-suite run has usually reached it.
    api.gate.create_session("register-contract-agent", scopes=["read"], tenant_id=tenant)

    body = haldir_client.get("/v1/agents", headers=_auth(bootstrap_key)).get_json()
    rows = [a for a in body["agents"] if a["agent_id"] == "register-contract-agent"]
    assert rows, "the register does not list the agent that just acted"

    read = _fields_read(_body_of("loadAgents"), "a")
    assert read, "the parse found no fields — the template moved and this went blind"
    missing = read - set(rows[0].keys())
    assert not missing, (
        f"dashboard.js's agents table reads {sorted(missing)}, which "
        f"/v1/agents does not return for an agent"
    )

    # The loader hoists these into locals, so the top-level parse above cannot
    # see them; they are the fields whose absence would silently blank a
    # column rather than fail loudly.
    for section, field in (("sessions", "total"), ("activity", "actions"),
                           ("activity", "cost_usd"), ("activity", "flagged")):
        assert field in rows[0][section], (
            f"dashboard.js reads {section}.{field}, which /v1/agents does not return"
        )
