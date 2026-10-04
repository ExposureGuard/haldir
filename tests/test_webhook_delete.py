"""Removing a webhook endpoint — and the dashboard page that removes it.

Three faults sat on top of each other, each hiding the next:

  * the store had no way to remove an endpoint at all;
  * `DELETE /v1/webhooks/<id>` did not exist, though the dashboard's Delete
    button has always called it — so the button 404'd and the row stayed;
  * `/v1/admin/overview` never set the `webhooks.webhooks` key the page
    renders from, so the page said "No webhooks registered" however many
    there were — and the table read `id` / `event` / `deliveries`, names no
    surface has ever returned.

Each link gets a test, plus the tenant-scoping rule the delete path has to
obey, plus a contract test that keeps the page and the payload in step.

Run: python -m pytest tests/test_webhook_delete.py -v
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_watch import WebhookManager  # noqa: E402


@pytest.fixture(autouse=True)
def _allow_unresolvable_test_urls(monkeypatch):
    """The address half of `safe_outbound_url` resolves every host, and the
    example URLs here do not resolve. Scoped to this module on purpose — the
    guard's default behaviour is what `test_outbound_url.py` asserts."""
    monkeypatch.setenv("HALDIR_ALLOW_PRIVATE_WEBHOOKS", "1")


def _register_via_http(client, key: str, url: str = "https://hooks.example.com/delete-me") -> dict:
    r = client.post(
        "/v1/webhooks",
        json={"url": url, "name": "delete-test"},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert r.status_code == 201, r.data
    return r.get_json()


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


# ── The store ───────────────────────────────────────────────────────────

def test_unregister_removes_the_endpoint(tmp_path) -> None:
    """`list_webhooks` reads the in-memory registry, not the table — so this
    asserts both: the row is gone from the database *and* the registry was
    refreshed, which is what stops the next event going to a receiver the
    operator just removed."""
    mgr = WebhookManager(db_path=str(tmp_path / "d1.db"))
    wh = mgr.register(url="https://hooks.example.com/a", tenant_id="tnt-A")
    assert mgr.unregister(wh.webhook_id, tenant_id="tnt-A") is True
    assert mgr.list_webhooks("tnt-A") == []


def test_unregister_is_tenant_scoped(tmp_path) -> None:
    """Wrong tenant and no-such-id are the same answer, so the result cannot
    be used to probe whether another tenant owns an id."""
    mgr = WebhookManager(db_path=str(tmp_path / "d2.db"))
    wh = mgr.register(url="https://hooks.example.com/b", tenant_id="tnt-A")
    assert mgr.unregister(wh.webhook_id, tenant_id="tnt-B") is False
    assert len(mgr.list_webhooks("tnt-A")) == 1


def test_unregister_unknown_id_is_false(tmp_path) -> None:
    mgr = WebhookManager(db_path=str(tmp_path / "d3.db"))
    assert mgr.unregister(999999, tenant_id="tnt-A") is False


# ── The route ───────────────────────────────────────────────────────────

def test_delete_endpoint_removes_and_reports(haldir_client, bootstrap_key) -> None:
    reg = _register_via_http(haldir_client, bootstrap_key)
    r = haldir_client.delete(
        f"/v1/webhooks/{reg['webhook_id']}", headers=_auth(bootstrap_key)
    )
    assert r.status_code == 200, r.data
    assert r.get_json() == {"deleted": True, "webhook_id": reg["webhook_id"]}

    listed = haldir_client.get("/v1/webhooks", headers=_auth(bootstrap_key)).get_json()
    assert all(w["webhook_id"] != reg["webhook_id"] for w in listed["webhooks"])


def test_delete_unknown_id_is_404(haldir_client, bootstrap_key) -> None:
    r = haldir_client.delete("/v1/webhooks/999999", headers=_auth(bootstrap_key))
    assert r.status_code == 404
    assert r.get_json()["code"] == "not_found"


def test_delete_twice_is_404_the_second_time(haldir_client, bootstrap_key) -> None:
    """Idempotence is not on offer here on purpose: the second answer is the
    same 404 a foreign id gets, which is what keeps the route from being an
    existence oracle."""
    reg = _register_via_http(haldir_client, bootstrap_key)
    first = haldir_client.delete(f"/v1/webhooks/{reg['webhook_id']}", headers=_auth(bootstrap_key))
    second = haldir_client.delete(f"/v1/webhooks/{reg['webhook_id']}", headers=_auth(bootstrap_key))
    assert first.status_code == 200
    assert second.status_code == 404


# ── The dashboard's data ────────────────────────────────────────────────

def _overview_row(client, key: str, webhook_id: int) -> dict:
    body = client.get("/v1/admin/overview", headers=_auth(key)).get_json()
    rows = body["webhooks"]["webhooks"]
    mine = [w for w in rows if w["webhook_id"] == webhook_id]
    assert mine, f"the overview does not list webhook {webhook_id}"
    return mine[0]


def test_the_overview_carries_the_endpoint_list(haldir_client, bootstrap_key) -> None:
    reg = _register_via_http(
        haldir_client, bootstrap_key, url="https://hooks.example.com/overview"
    )
    row = _overview_row(haldir_client, bootstrap_key, reg["webhook_id"])
    assert row["url"] == "https://hooks.example.com/overview"
    assert isinstance(row["events"], list) and row["events"]
    assert row["fire_count"] == 0
    assert row["success_rate"] is None, (
        "an endpoint nothing has ever reached has no success rate; 100% would "
        "call it healthy"
    )


def test_the_dashboard_reads_fields_the_overview_actually_returns(
    haldir_client, bootstrap_key
) -> None:
    """The break this file exists for, as one assertion.

    The page read `w.id`, `w.event` and `w.deliveries`; the API answers
    `webhook_id`, `events` and `fire_count`. Nothing compared the two, so
    every cell but the URL rendered empty. Parsing the real template means a
    rename on either side fails here rather than emptying a table.
    """
    reg = _register_via_http(
        haldir_client, bootstrap_key, url="https://hooks.example.com/contract"
    )
    keys = set(_overview_row(haldir_client, bootstrap_key, reg["webhook_id"]).keys())

    src = (Path(__file__).resolve().parent.parent / "dashboard.js").read_text(
        encoding="utf-8"
    )
    block = src[src.index("function loadWebhooks"):src.index("// ── Approvals page")]
    read = set(re.findall(r"\bw\.([a-zA-Z_]+)", block))
    assert read, "the parse found no fields — the template moved and this went blind"
    missing = read - keys
    assert not missing, (
        f"dashboard.js reads {sorted(missing)}, which /v1/admin/overview does "
        f"not return for an endpoint"
    )
