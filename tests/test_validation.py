"""
Tests for haldir_validation — the @validate_body decorator that replaces
ad-hoc data.get() + isinstance checks in Flask handlers.

Run: python -m pytest tests/test_validation.py -v
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Decorator behavior (unit, using a standalone Flask app) ─────────────

def _build_test_app():
    """A minimal Flask app with one /echo endpoint using @validate_body
    so we can drive the decorator directly without pulling in the whole
    Haldir surface area."""
    from flask import Flask, jsonify, request
    from haldir_validation import validate_body

    app = Flask(__name__)

    @app.route("/echo", methods=["POST"])
    @validate_body({
        "name":   {"type": str,   "required": True, "maxlen": 16},
        "count":  {"type": int,   "default": 1, "min": 1, "max": 100},
        "ratio":  {"type": float, "default": 1.0, "min": 0.0},
        "active": {"type": bool,  "default": False},
        "mode":   {"type": str,   "default": "normal",
                   "choices": ["normal", "strict", "audit"]},
        "tags":   {"type": list,  "default": []},
    })
    def echo():
        return jsonify(request.validated)

    return app.test_client()


def test_valid_body_populates_request_validated() -> None:
    client = _build_test_app()
    r = client.post("/echo", json={"name": "alice", "count": 5, "mode": "strict"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["name"] == "alice"
    assert body["count"] == 5
    assert body["mode"] == "strict"
    # Defaults filled in for omitted fields.
    assert body["ratio"] == 1.0
    assert body["active"] is False
    assert body["tags"] == []


def test_missing_required_field_returns_400() -> None:
    client = _build_test_app()
    r = client.post("/echo", json={"count": 5})
    assert r.status_code == 400
    body = r.get_json()
    assert body["code"] == "invalid_request"
    assert body["field"] == "name"
    assert "required" in body["reason"]


def test_wrong_type_returns_400() -> None:
    client = _build_test_app()
    r = client.post("/echo", json={"name": "x", "count": "not a number"})
    assert r.status_code == 400
    body = r.get_json()
    assert body["field"] == "count"
    assert "int" in body["reason"]


def test_int_rejects_bool_without_silent_coercion() -> None:
    """JSON `true`/`false` must not silently count as 1/0 — that hides
    client bugs and leads to $0.00 spend limits."""
    client = _build_test_app()
    r = client.post("/echo", json={"name": "x", "count": True})
    assert r.status_code == 400
    assert r.get_json()["field"] == "count"


def test_float_accepts_int() -> None:
    """JSON numbers can be int or float; int → float coercion is safe."""
    client = _build_test_app()
    r = client.post("/echo", json={"name": "x", "ratio": 3})
    assert r.status_code == 200
    assert r.get_json()["ratio"] == 3.0


def test_min_max_bounds_enforced() -> None:
    client = _build_test_app()
    r = client.post("/echo", json={"name": "x", "count": 0})
    assert r.status_code == 400
    assert r.get_json()["field"] == "count"

    r = client.post("/echo", json={"name": "x", "count": 999})
    assert r.status_code == 400
    assert r.get_json()["field"] == "count"


def test_maxlen_enforced() -> None:
    client = _build_test_app()
    r = client.post("/echo", json={"name": "x" * 100})
    assert r.status_code == 400
    assert r.get_json()["field"] == "name"


def test_choices_enforced() -> None:
    client = _build_test_app()
    r = client.post("/echo", json={"name": "x", "mode": "unknown"})
    assert r.status_code == 400
    assert r.get_json()["field"] == "mode"


def test_unknown_fields_ignored_for_forward_compat() -> None:
    """New SDK versions may send fields the server doesn't know yet.
    Accept and drop, don't reject."""
    client = _build_test_app()
    r = client.post("/echo", json={"name": "x", "unknown_future_field": 42})
    assert r.status_code == 200
    assert "unknown_future_field" not in r.get_json()


def test_non_object_body_returns_400() -> None:
    client = _build_test_app()
    r = client.post("/echo", data="[]", content_type="application/json")
    assert r.status_code == 400
    assert r.get_json()["code"] == "invalid_request"


def test_empty_body_triggers_missing_required() -> None:
    client = _build_test_app()
    r = client.post("/echo", json={})
    assert r.status_code == 400
    assert r.get_json()["field"] == "name"


# ── End-to-end via real /v1/sessions + /v1/payments endpoints ────────────

def test_sessions_rejects_missing_agent_id(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/sessions",
        json={"scopes": ["read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400
    assert r.get_json()["field"] == "agent_id"


def test_sessions_rejects_negative_ttl(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/sessions",
        json={"agent_id": "x", "ttl": -1},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400
    assert r.get_json()["field"] == "ttl"


def test_sessions_rejects_huge_ttl(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/sessions",
        json={"agent_id": "x", "ttl": 99999999},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400
    assert r.get_json()["field"] == "ttl"


def test_payments_rejects_zero_amount(haldir_client, bootstrap_key) -> None:
    """amount has min=0.01, so 0 must be rejected — prevents $0 auths
    that could still be counted as a payment event downstream."""
    r = haldir_client.post(
        "/v1/payments/authorize",
        json={"session_id": "sess_fake", "amount": 0},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400
    assert r.get_json()["field"] == "amount"


def test_payments_rejects_over_max_amount(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/payments/authorize",
        json={"session_id": "sess_fake", "amount": 2_000_000},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400
    assert r.get_json()["field"] == "amount"
