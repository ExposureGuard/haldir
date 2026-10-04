"""The dashboard reads fields the API actually returns.

This is a bug class, not a bug. The cloud dashboard's JavaScript (`dashboard.js`
— the page served at `/cloud/overview`) was written against payload shapes that
never existed, in three places that were each found separately:

  * the webhooks table read `w.id` / `w.event` / `w.deliveries` where the API
    answers `webhook_id` / `events` / `fire_count`;
  * the approvals table read `r.session_id` / `r.requested_by` /
    `r.requested_at`, and the approval row has `agent_id` / `created_at` and
    neither of the first two — half of every row rendered blank;
  * the compliance page read `schedules.next_due` when `next_due` is per
    schedule, so "Next pack due" showed "—" forever.

Nothing compared the two sides, so each was invisible until someone opened the
page with data in it. These tests parse the real template in `dashboard.js` and
resolve every field it reads against the real payload — a rename on either side
fails here instead of emptying a column.

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


def _register_webhook(client, key: str, url: str) -> dict:
    r = client.post("/v1/webhooks", json={"url": url, "name": "contract"},
                    headers=_auth(key))
    assert r.status_code == 201, r.data
    return r.get_json()


def _pending_approval(client, key: str) -> dict:
    """A real pending approval, because the row shape is the thing under test.

    The session is minted through the Gate rather than `POST /v1/sessions`:
    that route enforces the tenant's agent cap, and in a full-suite run the
    bootstrap tenant is usually at it, so the HTTP call 403s and this test
    fails for a reason that has nothing to do with approvals. (The same trap
    is why the note about it lives in this project's memory.)
    """
    import api

    tenant = client.get("/v1/admin/overview", headers=_auth(key)).get_json()["tenant_id"]
    session_id = api.gate.create_session(
        agent_id="contract-agent", scopes=["read"], ttl=600, tenant_id=tenant
    ).session_id

    r = client.post("/v1/approvals/request",
                    json={"session_id": session_id, "agent_id": "contract-agent",
                          "reason": "contract test", "ttl": 600},
                    headers=_auth(key))
    assert r.status_code == 201, r.data
    pending = client.get("/v1/approvals/pending", headers=_auth(key)).get_json()["requests"]
    row = [p for p in pending if p["request_id"] == r.get_json()["request_id"]]
    assert row, "the approval just created is not in the pending list"
    return row[0]


# ── Webhooks page ───────────────────────────────────────────────────────

def test_the_webhooks_table_reads_fields_the_overview_returns(haldir_client, bootstrap_key) -> None:
    reg = _register_webhook(haldir_client, bootstrap_key, "https://hooks.example.com/contract-wh")
    overview = haldir_client.get("/v1/admin/overview", headers=_auth(bootstrap_key)).get_json()
    rows = [w for w in overview["webhooks"]["webhooks"] if w["webhook_id"] == reg["webhook_id"]]
    assert rows, "the overview does not list the webhook that was just registered"

    read = _fields_read(_body_of("loadWebhooks"), "w")
    assert read, "the parse found no fields — the template moved and this went blind"
    missing = read - set(rows[0].keys())
    assert not missing, (
        f"dashboard.js's webhooks table reads {sorted(missing)}, which "
        f"/v1/admin/overview does not return for an endpoint"
    )


# ── Approvals page ──────────────────────────────────────────────────────

def test_the_approvals_table_reads_fields_the_pending_list_returns(
    haldir_client, bootstrap_key
) -> None:
    row = _pending_approval(haldir_client, bootstrap_key)
    read = _fields_read(_body_of("loadApprovals"), "r")
    assert read, "the parse found no fields — the template moved and this went blind"
    missing = read - set(row.keys())
    assert not missing, (
        f"dashboard.js's approvals table reads {sorted(missing)}, which "
        f"/v1/approvals/pending does not return for a request"
    )


# ── Compliance page ─────────────────────────────────────────────────────

def test_the_compliance_page_has_a_next_due_to_read(haldir_client, bootstrap_key) -> None:
    """`loadCompliance` takes the soonest `next_due` across the schedules. That
    only works while the rows carry one — and while the response does not, so
    that the earlier bug (reading a top-level key that was never there) would
    still be a bug if it came back."""
    r = haldir_client.post("/v1/compliance/schedules",
                           json={"name": "contract", "cadence": "weekly",
                                 "delivery": "email:compliance@example.com"},
                           headers=_auth(bootstrap_key))
    assert r.status_code in (200, 201), r.data

    body = haldir_client.get("/v1/compliance/schedules", headers=_auth(bootstrap_key)).get_json()
    assert "schedules" in body
    assert "next_due" not in body, (
        "a top-level next_due appeared; dashboard.js computes the soonest from "
        "the rows, and two answers to one question is how they disagree"
    )
    assert body["schedules"], "the schedule just created is missing"
    for s in body["schedules"]:
        assert "next_due" in s, "a schedule row has no next_due for the page to read"
        assert isinstance(s["next_due"], (int, float))
