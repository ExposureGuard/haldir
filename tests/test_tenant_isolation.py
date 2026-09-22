"""
Tenant isolation.

Two surfaces were found — by an independent review, then reproduced — handing
one tenant another tenant's data:

  * **`/v1/approvals/*` had no tenant concept at all.** `haldir_gate/approvals.py`
    accepted no tenant, stored none, and filtered on none. The column existed
    on `approval_requests` (added by `migrations/001_initial_schema.sql`) but
    every row in it was `''`. Any tenant could read another's request — reason
    text included — list every tenant's pending queue, and *approve or deny*
    another tenant's request.

  * **`WebhookManager` broadcast to every tenant.** `_load_webhooks()` loaded
    every active row in the process and `fire()` dispatched to all of them;
    the `tenant_id` argument was written onto the delivery row and never used
    for routing. One tenant's anomaly alerts, budget events, approval requests
    and full SOC2 evidence packs were POSTed to every other tenant's endpoints.

Both are the multi-tenancy break `THREAT_MODEL.md` ranks as the top-tier
threat. These tests assert them in both directions — the attacker's key must
fail, *and* the owner's must still work — because a fix that simply breaks the
feature would pass a one-sided test.

Run: python -m pytest tests/test_tenant_isolation.py -v
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import secrets
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import api  # noqa: E402
from haldir_db import get_db  # noqa: E402


def _mint_key_for(tenant_id: str) -> str:
    """An API key belonging to `tenant_id`, bypassing POST /v1/keys.

    That route derives the tenant from the key's own hash and only starts a
    fresh tenant when no other key exists — so a second tenant cannot be
    created through it without deleting the shared suite's bootstrap key.
    This inserts the row directly instead, leaving the shared state alone.
    """
    key = "hld_" + secrets.token_urlsafe(24)
    conn = get_db(api.DB_PATH)
    try:
        # Reuse whatever scope representation the app itself writes, so the
        # test does not depend on the serialization format.
        row = conn.execute("SELECT scopes FROM api_keys LIMIT 1").fetchone()
        scopes = row["scopes"] if row else '["*"]'
        conn.execute(
            "INSERT INTO api_keys (key_hash, key_prefix, tenant_id, name, tier, "
            "scopes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (hashlib.sha256(key.encode()).hexdigest(), key[:12], tenant_id,
             f"probe-{tenant_id[:8]}", "pro", scopes, time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    return key


def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture
def two_tenants(haldir_client):
    """Two tenants, each with its own key. A distinct suffix per run keeps
    the tenants from colliding with rows earlier runs left behind."""
    suffix = secrets.token_hex(4)
    return (
        f"tenant-a-{suffix}", _mint_key_for(f"tenant-a-{suffix}"),
        f"tenant-b-{suffix}", _mint_key_for(f"tenant-b-{suffix}"),
    )


# ── Approvals ────────────────────────────────────────────────────────

def _open_request(client, tenant, key, reason="ALPHA-SECRET-REASON"):
    """Create a pending approval request owned by `tenant`."""
    session = api.gate.create_session(
        f"agent-{tenant[:8]}", scopes=["read"], ttl=3600, tenant_id=tenant,
    )
    r = client.post(
        "/v1/approvals/request",
        json={"session_id": session.session_id, "action": "wire-transfer",
              "reason": reason, "ttl": 3600},
        headers=_auth(key),
    )
    assert r.status_code == 201, r.data
    return r.get_json()["request_id"]


def test_a_request_is_filed_under_its_own_tenant(haldir_client, two_tenants) -> None:
    """The column was always there; nothing ever wrote to it. Without this
    the filter below would have nothing to filter on."""
    tenant_a, key_a, _, _ = two_tenants
    req_id = _open_request(haldir_client, tenant_a, key_a)

    conn = get_db(api.DB_PATH)
    try:
        row = conn.execute(
            "SELECT tenant_id FROM approval_requests WHERE request_id = ?",
            (req_id,),
        ).fetchone()
    finally:
        conn.close()
    assert row["tenant_id"] == tenant_a, (
        "the request was stored without its tenant, so no scoped read can "
        "distinguish it from anyone else's"
    )


def test_another_tenant_cannot_read_a_request(haldir_client, two_tenants) -> None:
    tenant_a, key_a, _, key_b = two_tenants
    req_id = _open_request(haldir_client, tenant_a, key_a)

    # The owner still sees it.
    assert haldir_client.get(f"/v1/approvals/{req_id}",
                             headers=_auth(key_a)).status_code == 200

    r = haldir_client.get(f"/v1/approvals/{req_id}", headers=_auth(key_b))
    assert r.status_code == 404, (
        f"tenant B read tenant A's approval request: {r.status_code} {r.data}"
    )
    assert b"ALPHA-SECRET-REASON" not in r.data


def test_another_tenant_cannot_see_it_in_the_pending_queue(
    haldir_client, two_tenants
) -> None:
    tenant_a, key_a, _, key_b = two_tenants
    _open_request(haldir_client, tenant_a, key_a)

    mine = haldir_client.get("/v1/approvals/pending", headers=_auth(key_a)).get_json()
    assert any(r_["action"] == "wire-transfer" for r_ in mine["requests"]), (
        "the owner can no longer see its own pending request"
    )

    theirs = haldir_client.get("/v1/approvals/pending", headers=_auth(key_b)).get_json()
    assert not any(r_["action"] == "wire-transfer" for r_ in theirs["requests"]), (
        f"tenant B's pending queue contains tenant A's request: {theirs}"
    )


def test_another_tenant_cannot_approve(haldir_client, two_tenants) -> None:
    """The sharp end: this was not just disclosure. B could decide A's
    request — the human-in-the-loop gate, opened by the wrong human."""
    tenant_a, key_a, _, key_b = two_tenants
    req_id = _open_request(haldir_client, tenant_a, key_a)

    r = haldir_client.post(f"/v1/approvals/{req_id}/approve",
                           json={"note": "pwned-by-beta"}, headers=_auth(key_b))
    assert r.status_code == 400, (
        f"tenant B approved tenant A's request: {r.status_code} {r.data}"
    )

    still = haldir_client.get(f"/v1/approvals/{req_id}",
                              headers=_auth(key_a)).get_json()
    assert still["status"] == "pending"
    assert still["decision_note"] != "pwned-by-beta"

    # And the owner can still decide its own.
    assert haldir_client.post(f"/v1/approvals/{req_id}/approve",
                              json={"note": "ok"}, headers=_auth(key_a),
                              ).status_code == 200


# ── Webhooks ─────────────────────────────────────────────────────────

class _Receiver:
    """A real HTTP endpoint, because the bug was in delivery, not in a
    return value — anything that stops short of an actual POST would have
    passed while the leak was live."""

    def __init__(self) -> None:
        self.hits: list[dict] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                outer.hits.append(json.loads(self.rfile.read(length)))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_: object) -> None:
                return

        self._server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}/hook"

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def receivers(monkeypatch):
    monkeypatch.setenv("HALDIR_ALLOW_PRIVATE_WEBHOOKS", "1")
    a, b = _Receiver(), _Receiver()
    yield a, b
    a.stop()
    b.stop()


def _register_for(client, tenant, key, url):
    r = client.post("/v1/webhooks", json={"url": url, "events": ["all"]},
                    headers=_auth(key))
    assert r.status_code == 201, r.data
    return r.get_json()


def test_an_event_reaches_only_its_own_tenants_endpoint(
    haldir_client, two_tenants, receivers
) -> None:
    tenant_a, key_a, tenant_b, key_b = two_tenants
    rec_a, rec_b = receivers

    _register_for(haldir_client, tenant_a, key_a, rec_a.url)
    _register_for(haldir_client, tenant_b, key_b, rec_b.url)

    api.webhook_mgr.fire(
        "anomaly", {"agent": "alpha-agent", "secret": "ALPHA-ONLY"},
        tenant_id=tenant_a,
    )

    deadline = time.time() + 20
    while time.time() < deadline and not (rec_a.hits or rec_b.hits):
        time.sleep(0.05)
    time.sleep(0.5)  # let any second (wrong) delivery arrive before asserting

    assert rec_a.hits, "the owning tenant's endpoint received nothing at all"
    assert not rec_b.hits, (
        f"another tenant's endpoint received the event: {rec_b.hits}"
    )
    assert rec_b.hits == [] or "ALPHA-ONLY" not in json.dumps(rec_b.hits)


def test_a_tenant_cannot_list_anothers_endpoints(haldir_client, two_tenants) -> None:
    """Knowing the URL is the first step to aiming at it."""
    tenant_a, key_a, _, key_b = two_tenants

    r = haldir_client.post("/v1/webhooks",
                           json={"url": "https://example.com/alpha-hook",
                                 "name": "alpha's slack", "events": ["all"]},
                           headers=_auth(key_a))
    assert r.status_code in (201, 400), r.data  # 400 only if the URL is refused

    listed = haldir_client.get("/v1/webhooks", headers=_auth(key_b)).get_json()
    urls = [w["url"] for w in listed["webhooks"]]
    assert "https://example.com/alpha-hook" not in urls, (
        f"tenant B can enumerate tenant A's endpoints: {listed}"
    )
