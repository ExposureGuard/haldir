"""
Tests for webhook signature rotation — Stripe-style overlap window.

Scope:
  - rotate_secret() returns new + previous secrets + grace expiry
  - rotate_secret() actually swaps in the DB
  - rotate_secret() is tenant-scoped (returns None for wrong tenant)
  - verify_signature accepts a list of secrets — either matches
  - verify_signature still accepts a single string (back-compat)
  - verify_signature raises on empty / all-empty secrets
  - HTTP endpoint POST /v1/webhooks/<id>/rotate-secret returns both
    secrets, requires webhooks:write scope, 404 on wrong-tenant id

Run: python -m pytest tests/test_webhook_rotation.py -v
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from haldir_watch.webhooks import (  # noqa: E402
    WebhookManager,
    WebhookVerificationError,
    verify_signature,
)


# ── verify_signature with multi-secret ───────────────────────────────

def _sign(payload: bytes, secret: str, ts: int | None = None) -> tuple[str, str]:
    """Helper: returns (signature_header, timestamp_header) for a
    payload signed with `secret`."""
    if ts is None:
        ts = int(time.time())
    signing_input = f"{ts}.".encode() + payload
    mac = hmac.new(secret.encode(), signing_input, hashlib.sha256).hexdigest()
    return f"sha256={mac}", str(ts)


def test_verify_with_string_secret_still_works() -> None:
    """Back-compat: existing receivers pass a single string."""
    payload = b'{"event":"x"}'
    sig, ts = _sign(payload, "old-secret")
    verify_signature(payload, sig, ts, "old-secret")  # no raise = pass


def test_verify_with_list_either_secret_authenticates() -> None:
    """During rotation overlap, the receiver tries both — either
    valid one accepts the payload."""
    payload = b'{"event":"x"}'
    sig_old, ts = _sign(payload, "old-secret")
    sig_new, ts2 = _sign(payload, "new-secret")
    # Old secret signed it → list with both still passes.
    verify_signature(payload, sig_old, ts, ["new-secret", "old-secret"])
    # New secret signed it → list with both still passes.
    verify_signature(payload, sig_new, ts2, ["new-secret", "old-secret"])


def test_verify_with_list_all_wrong_raises() -> None:
    payload = b'{"event":"x"}'
    sig, ts = _sign(payload, "real-secret")
    with pytest.raises(WebhookVerificationError, match="does not match"):
        verify_signature(payload, sig, ts, ["wrong-1", "wrong-2"])


def test_verify_filters_empty_strings_in_list() -> None:
    """An empty-string secret hash-collides with itself trivially —
    must NOT silently authenticate. Filter empties out, fail closed
    if nothing real remains."""
    payload = b'{"event":"x"}'
    sig, ts = _sign(payload, "real")
    # Empty + valid: still passes (real is in the list).
    verify_signature(payload, sig, ts, ["", "real"])
    # All empty: raises.
    with pytest.raises(WebhookVerificationError, match="No secret"):
        verify_signature(payload, sig, ts, ["", ""])


def test_verify_with_empty_string_secret_raises() -> None:
    """Single empty-string secret: same defense, raises."""
    payload = b"x"
    sig, ts = _sign(payload, "real")
    with pytest.raises(WebhookVerificationError, match="No secret"):
        verify_signature(payload, sig, ts, "")


# ── rotate_secret on the manager ────────────────────────────────────

def test_rotate_returns_both_secrets(tmp_path) -> None:
    """Mint a webhook, rotate, assert both secrets come back + the
    previous one matches what was on file before."""
    db = str(tmp_path / "rot.db")
    mgr = WebhookManager(db_path=db)
    wh = mgr.register(
        url="https://hooks.example.com/x",
        name="rot-test",
        tenant_id="tnt-rot",
    )
    original_secret = wh.secret
    assert wh.webhook_id > 0

    out = mgr.rotate_secret(wh.webhook_id, tenant_id="tnt-rot")
    assert out is not None
    assert out["secret"] and out["secret"] != original_secret
    assert out["secret_prev"] == original_secret
    assert out["secret_prev_expires_at"] > time.time()
    assert out["grace_seconds"] == 24 * 3600


def test_rotate_persists_swap_in_db(tmp_path) -> None:
    """After rotate, the manager's in-memory cache reflects the new
    primary secret (so subsequent fires sign with it)."""
    db = str(tmp_path / "rot2.db")
    mgr = WebhookManager(db_path=db)
    wh = mgr.register(
        url="https://hooks.example.com/y",
        tenant_id="tnt-rot",
    )
    out = mgr.rotate_secret(wh.webhook_id, tenant_id="tnt-rot")
    assert out is not None

    # The reloaded WebhookConfig should now have the new secret.
    found = next(
        (w for w in mgr._webhooks if w.url == "https://hooks.example.com/y"),
        None,
    )
    assert found is not None
    assert found.secret == out["secret"]
    assert found.secret != out["secret_prev"]


def test_rotate_is_tenant_scoped(tmp_path) -> None:
    db = str(tmp_path / "rot3.db")
    mgr = WebhookManager(db_path=db)
    wh = mgr.register(
        url="https://hooks.example.com/z",
        tenant_id="tnt-A",
    )
    # Wrong tenant: returns None.
    assert mgr.rotate_secret(wh.webhook_id, tenant_id="tnt-B") is None


def test_rotate_unknown_id_returns_none(tmp_path) -> None:
    db = str(tmp_path / "rot4.db")
    mgr = WebhookManager(db_path=db)
    assert mgr.rotate_secret(99999, tenant_id="tnt-X") is None


# ── HTTP endpoint integration ──────────────────────────────────────

def _register_via_http(haldir_client, key: str) -> dict:
    r = haldir_client.post(
        "/v1/webhooks",
        json={"url": "https://hooks.example.com/rotate-test",
              "name": "rotate-http"},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert r.status_code == 201, r.data
    return r.get_json()


def test_rotate_endpoint_returns_both_secrets(haldir_client, bootstrap_key) -> None:
    reg = _register_via_http(haldir_client, bootstrap_key)
    assert reg["webhook_id"] > 0

    r = haldir_client.post(
        f"/v1/webhooks/{reg['webhook_id']}/rotate-secret",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["webhook_id"] == reg["webhook_id"]
    assert body["secret"] and body["secret"] != reg["secret"]
    assert body["secret_prev"] == reg["secret"]
    assert body["secret_prev_expires_at"] > time.time()


def test_rotate_endpoint_404_on_unknown_id(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/webhooks/999999/rotate-secret",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 404


def test_rotate_endpoint_requires_webhooks_write_scope(haldir_client, bootstrap_key) -> None:
    reg = _register_via_http(haldir_client, bootstrap_key)
    # Mint a key without webhooks:write.
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "ro-rotate", "scopes": ["webhooks:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    ro_key = r.get_json()["key"]
    r2 = haldir_client.post(
        f"/v1/webhooks/{reg['webhook_id']}/rotate-secret",
        headers={"Authorization": f"Bearer {ro_key}"},
    )
    assert r2.status_code == 403
    assert r2.get_json()["required"] == "webhooks:write"


def test_rotate_endpoint_grace_seconds_clamps_safely(haldir_client, bootstrap_key) -> None:
    """grace_seconds is bounded to [60, 7d]. An absurd value gets
    clamped, not rejected."""
    reg = _register_via_http(haldir_client, bootstrap_key)
    r = haldir_client.post(
        f"/v1/webhooks/{reg['webhook_id']}/rotate-secret?grace_seconds=99999999",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    actual_grace = r.get_json()["grace_seconds"]
    assert actual_grace == 7 * 24 * 3600
