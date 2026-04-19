"""
Tests for webhook delivery: headers, retries, and the deliveries log.

Scope:
  - Every fire sends X-Haldir-Webhook-Id (same across retries of the
    same event) + X-Haldir-Delivery-Attempt (increments)
  - Transient 5xx / network errors trigger retry with exponential
    backoff, up to MAX_DELIVERY_ATTEMPTS
  - 4xx is treated as a permanent failure — no retry
  - 2xx short-circuits the retry loop
  - Every attempt (success or failure) is logged to webhook_deliveries
  - GET /v1/webhooks/deliveries lists them per-tenant
  - SDK re-exports verify_webhook_signature under the top-level name

Run: python -m pytest tests/test_webhook_delivery.py -v
"""

from __future__ import annotations

import http.server
import json
import os
import sqlite3
import sys
import threading
import time
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from haldir_watch.webhooks import (  # noqa: E402
    MAX_DELIVERY_ATTEMPTS,
    WebhookConfig,
    WebhookManager,
)


# ── Test server that returns configured status codes ────────────────

class _FakeReceiver:
    """Tiny HTTP server whose response code is driven by a queue. Each
    request consumes one status from `self.status_queue`; if the queue
    is exhausted we default to 200. Every request also gets recorded
    in `self.received` so tests can inspect headers/body."""

    def __init__(self) -> None:
        self.status_queue: list[int] = []
        self.received: list[dict[str, Any]] = []
        self._server: http.server.HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> str:
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                outer.received.append({
                    "headers": dict(self.headers),
                    "body":    body,
                    "path":    self.path,
                })
                status = outer.status_queue.pop(0) if outer.status_queue else 200
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_: Any, **__: Any) -> None:
                return  # quiet the stderr spam

        self._server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
        )
        self._thread.start()
        host, port = self._server.server_address
        return f"http://{host}:{port}/hook"

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()


@pytest.fixture
def receiver():
    r = _FakeReceiver()
    url = r.start()
    yield r, url
    r.stop()


@pytest.fixture
def manager(tmp_path):
    """A manager backed by its own SQLite DB with the deliveries table
    already created. Avoids coupling to whatever state shared fixtures
    leave behind."""
    db = str(tmp_path / "wh.db")
    # Apply migrations to bring the schema up.
    import haldir_migrate
    haldir_migrate.apply_pending(db)
    m = WebhookManager(db_path=db)
    return m


# ── Header contract ────────────────────────────────────────────────────

def test_fire_returns_event_id(receiver, manager) -> None:
    _, url = receiver
    manager.register(url=url, events=["all"], generate_secret=False)
    event_id = manager.fire("anomaly", {"agent": "a"})
    assert isinstance(event_id, str) and len(event_id) >= 16


def test_delivery_headers_include_webhook_id_and_attempt(receiver, manager) -> None:
    rec, url = receiver
    manager.register(url=url, events=["all"])
    event_id = manager.fire("anomaly", {"agent": "a"})
    _wait_until(lambda: len(rec.received) == 1)
    h = rec.received[0]["headers"]
    assert h.get("X-Haldir-Webhook-Id") == event_id
    assert h.get("X-Haldir-Delivery-Attempt") == "1"
    assert h.get("X-Haldir-Event") == "anomaly"
    # Signature header present because generate_secret defaults True.
    assert h.get("X-Haldir-Signature", "").startswith("sha256=")


# ── Retry on transient failures ────────────────────────────────────────

def test_500_triggers_retry_then_succeeds(receiver, manager) -> None:
    rec, url = receiver
    rec.status_queue = [500, 200]
    manager.register(url=url, events=["all"])
    event_id = manager.fire("anomaly", {"agent": "a"})
    _wait_until(lambda: len(rec.received) == 2, timeout_s=30)
    # Same event_id, incremented attempt.
    assert rec.received[0]["headers"]["X-Haldir-Webhook-Id"] == event_id
    assert rec.received[1]["headers"]["X-Haldir-Webhook-Id"] == event_id
    assert rec.received[0]["headers"]["X-Haldir-Delivery-Attempt"] == "1"
    assert rec.received[1]["headers"]["X-Haldir-Delivery-Attempt"] == "2"


def test_4xx_is_not_retried(receiver, manager) -> None:
    rec, url = receiver
    rec.status_queue = [400, 400, 400]
    manager.register(url=url, events=["all"])
    manager.fire("anomaly", {"agent": "a"})
    # Give the thread time to attempt (no retry expected).
    _wait_until(lambda: len(rec.received) >= 1, timeout_s=5)
    time.sleep(0.3)
    assert len(rec.received) == 1


def test_gives_up_after_max_attempts(receiver, manager) -> None:
    rec, url = receiver
    rec.status_queue = [500] * (MAX_DELIVERY_ATTEMPTS + 2)
    manager.register(url=url, events=["all"])
    manager.fire("anomaly", {"agent": "a"})
    _wait_until(
        lambda: len(rec.received) >= MAX_DELIVERY_ATTEMPTS,
        timeout_s=60,
    )
    # Wait a bit more and assert we never exceeded the cap.
    time.sleep(0.5)
    assert len(rec.received) == MAX_DELIVERY_ATTEMPTS


# ── Deliveries persistence ─────────────────────────────────────────────

def test_every_attempt_is_logged(receiver, manager) -> None:
    rec, url = receiver
    rec.status_queue = [500, 200]
    wh = manager.register(url=url, events=["all"])
    event_id = manager.fire("anomaly", {"agent": "a"}, tenant_id="t1")
    _wait_until(lambda: len(rec.received) == 2, timeout_s=30)

    # Give the log-write thread a beat to flush.
    _wait_until(
        lambda: len(manager.list_deliveries(tenant_id="t1", event_id=event_id)) == 2,
        timeout_s=5,
    )
    deliveries = manager.list_deliveries(tenant_id="t1", event_id=event_id)
    # Newest first.
    assert deliveries[0]["attempt"] == 2
    assert deliveries[0]["status_code"] == 200
    assert deliveries[1]["attempt"] == 1
    assert deliveries[1]["status_code"] == 500
    assert all(d["webhook_url"] == wh.url for d in deliveries)


def test_list_deliveries_filters_by_tenant(receiver, manager) -> None:
    _, url = receiver
    manager.register(url=url, events=["all"])
    manager.fire("anomaly", {"agent": "a"}, tenant_id="alpha")
    manager.fire("anomaly", {"agent": "b"}, tenant_id="beta")
    _wait_until(lambda: len(manager.list_deliveries("alpha")) >= 1, timeout_s=5)
    _wait_until(lambda: len(manager.list_deliveries("beta"))  >= 1, timeout_s=5)

    alpha = manager.list_deliveries("alpha")
    beta  = manager.list_deliveries("beta")
    assert all(d["event_id"] for d in alpha)
    assert all(d["event_id"] for d in beta)
    # No cross-tenant leakage.
    alpha_ids = {d["event_id"] for d in alpha}
    beta_ids  = {d["event_id"] for d in beta}
    assert alpha_ids.isdisjoint(beta_ids)


# ── HTTP endpoint integration ──────────────────────────────────────────

def test_deliveries_endpoint_returns_rows(haldir_client, bootstrap_key) -> None:
    """The /v1/webhooks/deliveries endpoint must be reachable, require
    auth, and return a well-shaped JSON payload. Actual delivery rows
    depend on what prior tests fired, so we only assert on shape."""
    r = haldir_client.get(
        "/v1/webhooks/deliveries",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert "deliveries" in body
    assert isinstance(body["deliveries"], list)


def test_deliveries_endpoint_requires_auth(haldir_client) -> None:
    r = haldir_client.get("/v1/webhooks/deliveries")
    assert r.status_code in (401, 403)


# ── SDK re-export ─────────────────────────────────────────────────────

def test_sdk_reexports_verify_webhook_signature() -> None:
    """Customer-facing import should succeed as `from haldir import ...`
    if the package is installed, or via `import sdk` in-repo."""
    import sdk
    assert hasattr(sdk, "verify_webhook_signature")
    assert hasattr(sdk, "WebhookVerificationError")

    # Identity check — they must be the same callables as in the
    # internal module, not accidental shadow definitions.
    from haldir_watch.webhooks import (
        verify_signature,
        WebhookVerificationError,
    )
    assert sdk.verify_webhook_signature is verify_signature
    assert sdk.WebhookVerificationError is WebhookVerificationError


# ── Helpers ───────────────────────────────────────────────────────────

def _wait_until(predicate, timeout_s: float = 2.0, interval: float = 0.05) -> None:
    """Spin-wait on a boolean predicate. Fires AssertionError if the
    predicate doesn't become truthy in time."""
    end = time.time() + timeout_s
    while time.time() < end:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError(f"predicate never became truthy within {timeout_s}s")
