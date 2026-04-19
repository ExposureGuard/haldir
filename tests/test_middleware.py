"""
Tests for platform middleware — the request-ID, security header, body-size,
rate-limit header, and JSON error-handler plumbing that sits in front of
every /v1/ request.

Run: python -m pytest tests/test_middleware.py -v
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402


# ── Request-ID propagation ───────────────────────────────────────────────

def test_request_id_generated_when_absent(haldir_client) -> None:
    """Every response carries an X-Request-ID, even without one inbound."""
    r = haldir_client.get("/healthz")
    assert r.status_code == 200
    rid = r.headers.get("X-Request-ID")
    assert rid
    assert len(rid) >= 8


def test_request_id_echoed_from_inbound_header(haldir_client) -> None:
    """If the client sends X-Request-ID, we echo it so a single ID flows
    across the full stack (LB -> Haldir -> upstream)."""
    incoming = "abc123-trace-id"
    r = haldir_client.get("/healthz", headers={"X-Request-ID": incoming})
    assert r.headers.get("X-Request-ID") == incoming


def test_request_id_length_capped(haldir_client) -> None:
    """Pathologically long inbound IDs are truncated to prevent
    header-injection / log-flooding tricks."""
    crazy = "x" * 1000
    r = haldir_client.get("/healthz", headers={"X-Request-ID": crazy})
    assert len(r.headers.get("X-Request-ID", "")) <= 64


def test_request_id_unique_per_request(haldir_client) -> None:
    """Two requests without inbound IDs get distinct IDs."""
    r1 = haldir_client.get("/healthz")
    r2 = haldir_client.get("/healthz")
    assert r1.headers["X-Request-ID"] != r2.headers["X-Request-ID"]


# ── Security headers ─────────────────────────────────────────────────────

def test_security_headers_present(haldir_client) -> None:
    """Every response carries the baseline defense-in-depth header set."""
    r = haldir_client.get("/healthz")
    h = r.headers
    assert h.get("X-Content-Type-Options") == "nosniff"
    assert h.get("X-Frame-Options") == "DENY"
    assert h.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "max-age=" in h.get("Strict-Transport-Security", "")
    assert "camera=()" in h.get("Permissions-Policy", "")


def test_security_headers_applied_to_errors_too(haldir_client) -> None:
    """404s / 500s must still carry security headers — a browser rendering
    an error response shouldn't get a weaker posture than a successful one."""
    r = haldir_client.get("/this/does/not/exist")
    assert r.status_code == 404
    assert r.headers.get("X-Content-Type-Options") == "nosniff"


# ── Unified JSON error envelope ──────────────────────────────────────────

def test_404_returns_json(haldir_client) -> None:
    r = haldir_client.get("/definitely-not-a-real-route")
    assert r.status_code == 404
    assert r.content_type.startswith("application/json")
    body = r.get_json()
    assert body["code"] == "not_found"
    assert body["request_id"]


def test_405_returns_json(haldir_client) -> None:
    """Wrong method on a real endpoint returns JSON, not HTML."""
    r = haldir_client.delete("/healthz")  # healthz is GET-only
    assert r.status_code == 405
    body = r.get_json()
    assert body["code"] == "method_not_allowed"


def test_error_envelope_carries_request_id(haldir_client) -> None:
    """Errors include the request_id so support tickets are traceable
    back to a specific server log line."""
    r = haldir_client.get("/nope", headers={"X-Request-ID": "trace-xyz"})
    assert r.status_code == 404
    assert r.get_json()["request_id"] == "trace-xyz"


# ── Body size limit ─────────────────────────────────────────────────────

def test_max_content_length_configured() -> None:
    """MAX_CONTENT_LENGTH is set to 1 MiB — every mutating endpoint
    inherits the same Flask-level guard against oversize bodies."""
    assert api.app.config["MAX_CONTENT_LENGTH"] == 1024 * 1024


def test_oversize_body_returns_413_json(haldir_client, bootstrap_key) -> None:
    """A >1 MiB body is rejected with our JSON error envelope.

    Uses /v1/sessions with a valid API key so auth passes; the body-size
    check then fires when the handler accesses request.json. Confirms
    that (a) oversize bodies are rejected, and (b) the 413 goes through
    our JSON error handler rather than Flask's HTML default."""
    big = "x" * (2 * 1024 * 1024)
    r = haldir_client.post(
        "/v1/sessions",
        data='{"agent_id": "a", "blob":"' + big + '"}',
        content_type="application/json",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 413
    body = r.get_json()
    assert body["code"] == "payload_too_large"
    assert "max_bytes" in body


# ── Rate-limit headers ──────────────────────────────────────────────────

def test_rate_limit_headers_on_authenticated_request(haldir_client, bootstrap_key) -> None:
    """An authenticated /v1/ request exposes remaining quota so callers
    can self-pace before hitting 429."""
    r = haldir_client.post(
        "/v1/sessions",
        json={"agent_id": "rl-test", "scopes": ["read"], "ttl": 60},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code in (201, 200)
    assert r.headers.get("X-RateLimit-Limit")
    assert r.headers.get("X-RateLimit-Remaining") is not None
    assert r.headers.get("X-RateLimit-Reset")
    assert int(r.headers["X-RateLimit-Remaining"]) <= int(r.headers["X-RateLimit-Limit"])
