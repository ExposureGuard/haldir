"""
Tests for haldir_transparency_mirror — the external-log anchor that
closes THREAT_MODEL.md §10.3.

Scope:
  - Backend dispatch: none / file / http / rekor / unknown
  - File backend: writes JSONL, returns byte offset as log_index,
    never silently creates missing parent directories
  - HTTP backend: POSTs STH; success-path returns body as receipt;
    4xx/5xx surface as error receipt; network errors surface as error
    receipt; NEVER raises
  - Rekor backend: requires Ed25519-signed STH (HMAC is rejected
    with a clear error); encodes public key as PEM correctly;
    constructs hashedrekord shape Rekor will accept
  - record_receipt / list_receipts round-trip via DB, with tenant
    isolation and tree_size filtering
  - Hook contract: mirror_and_record is best-effort; a crashing
    backend NEVER leaks the exception to the caller
  - STH-signing path: get_tree_head writes a mirror receipt per call
    when HALDIR_TRANSPARENCY_MIRROR is set

Run: python -m pytest tests/test_transparency_mirror.py -v
"""

from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
import httpx  # noqa: E402

import haldir_transparency_mirror as mirror  # noqa: E402


def _sth(**overrides) -> dict:
    """Typical Ed25519-signed STH shape."""
    base = {
        "tree_size":  7,
        "root_hash":  "ab" * 32,
        "algorithm":  "Ed25519-over-canonical-sth",
        "signature":  "cd" * 64,
        "signed_at":  1_700_000_000,
        "key_id":     "0123456789abcdef",
        "public_key": "ef" * 32,
    }
    base.update(overrides)
    return base


def _isolated_db(tmp_path) -> str:
    import haldir_migrate
    db = str(tmp_path / "mirror.db")
    haldir_migrate.apply_pending(db)
    return db


# ── Dispatch ──────────────────────────────────────────────────────

def test_default_backend_is_none(monkeypatch) -> None:
    monkeypatch.delenv("HALDIR_TRANSPARENCY_MIRROR", raising=False)
    r = mirror.publish(_sth(), tenant_id="t")
    assert r["backend"] == "none"
    assert r["success"] is False
    assert "disabled" in r["error_message"]


def test_unknown_backend_returns_structured_error(monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_TRANSPARENCY_MIRROR", "sputnik://doge")
    r = mirror.publish(_sth(), tenant_id="t")
    assert r["backend"] == "unknown"
    assert r["success"] is False
    assert "unknown backend" in r["error_message"]


# ── File backend ───────────────────────────────────────────────────

def test_file_backend_writes_jsonl(tmp_path, monkeypatch) -> None:
    path = tmp_path / "sth.jsonl"
    monkeypatch.setenv("HALDIR_TRANSPARENCY_MIRROR", f"file:{path}")
    r = mirror.publish(_sth(tree_size=1), tenant_id="tnt-A")
    assert r["success"] is True
    assert r["backend"] == f"file:{path}"
    assert r["log_index"] == 0  # first write, offset 0
    # File has one line with the STH record.
    with open(path) as f:
        lines = f.readlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["tenant_id"] == "tnt-A"
    assert rec["sth"]["tree_size"] == 1


def test_file_backend_appends_offset_grows(tmp_path, monkeypatch) -> None:
    path = tmp_path / "sth.jsonl"
    monkeypatch.setenv("HALDIR_TRANSPARENCY_MIRROR", f"file:{path}")
    r1 = mirror.publish(_sth(tree_size=1), tenant_id="t")
    r2 = mirror.publish(_sth(tree_size=2), tenant_id="t")
    assert r1["log_index"] == 0
    assert r2["log_index"] > 0, (
        "second write must record a non-zero byte offset"
    )
    assert r2["receipt_id"] != r1["receipt_id"]  # different content → diff sha


def test_file_backend_rejects_missing_parent_dir(tmp_path, monkeypatch) -> None:
    path = tmp_path / "nonexistent" / "sth.jsonl"
    monkeypatch.setenv("HALDIR_TRANSPARENCY_MIRROR", f"file:{path}")
    r = mirror.publish(_sth(), tenant_id="t")
    assert r["success"] is False
    assert "does not exist" in r["error_message"]


def test_file_backend_rejects_empty_path(monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_TRANSPARENCY_MIRROR", "file:")
    r = mirror.publish(_sth(), tenant_id="t")
    assert r["success"] is False
    assert "requires a path" in r["error_message"]


# ── HTTP backend ───────────────────────────────────────────────────

class _FakeTransport(httpx.BaseTransport):
    """Captures the outbound POST + returns a canned response."""
    def __init__(self, status: int = 200, body: dict | None = None):
        self.status = status
        self.body = body if body is not None else {}
        self.captured: httpx.Request | None = None

    def handle_request(self, req: httpx.Request) -> httpx.Response:
        self.captured = req
        return httpx.Response(
            status_code=self.status,
            content=json.dumps(self.body).encode(),
            headers={"Content-Type": "application/json"},
            request=req,
        )


# Snapshot the real httpx.Client BEFORE any tests monkeypatch it. The
# backend patches call httpx.Client recursively otherwise — they'd
# each call the patched factory which tries to build a new
# httpx.Client, which is the patched factory again. Hello stack
# overflow.
_REAL_HTTPX_CLIENT = httpx.Client


def _patch_client_with(monkeypatch, transport: httpx.BaseTransport) -> None:
    """Monkeypatch httpx.Client so that constructing one with ANY
    kwargs builds on top of our fake transport. Uses the snapshotted
    real class under the hood to avoid infinite recursion."""
    def _factory(**kwargs):
        # Drop any transport the caller passed; we want ours. Accept
        # every other kwarg (timeout, headers, base_url, etc.) so the
        # signature matches whatever the backend uses.
        kwargs.pop("transport", None)
        return _REAL_HTTPX_CLIENT(transport=transport, **kwargs)
    monkeypatch.setattr(httpx, "Client", _factory)


def test_http_backend_success(monkeypatch) -> None:
    monkeypatch.setenv(
        "HALDIR_TRANSPARENCY_MIRROR",
        "https://archiver.example.com/log",
    )
    fake = _FakeTransport(status=201, body={"id": "rec-abc", "logIndex": 42})
    _patch_client_with(monkeypatch, fake)

    r = mirror.publish(_sth(), tenant_id="t")
    assert r["success"] is True
    assert r["receipt_id"] == "rec-abc"
    assert r["log_index"] == 42
    assert fake.captured is not None
    assert str(fake.captured.url).endswith("/log")
    body = json.loads(bytes(fake.captured.content))
    assert body["tenant_id"] == "t"
    assert body["sth"]["tree_size"] == 7


def test_http_backend_4xx_surfaces_as_error(monkeypatch) -> None:
    monkeypatch.setenv(
        "HALDIR_TRANSPARENCY_MIRROR", "https://archiver.example.com/log",
    )
    fake = _FakeTransport(status=400, body={"error": "bad shape"})
    _patch_client_with(monkeypatch, fake)
    r = mirror.publish(_sth(), tenant_id="t")
    assert r["success"] is False
    assert "http 400" in r["error_message"]


def test_http_backend_network_error_never_raises(monkeypatch) -> None:
    """Mirror failure MUST NOT propagate — the caller's STH response
    is the load-bearing thing."""
    monkeypatch.setenv(
        "HALDIR_TRANSPARENCY_MIRROR", "http://does-not-resolve.invalid/",
    )

    class _BoomTransport(httpx.BaseTransport):
        def handle_request(self, req):
            raise httpx.ConnectError("boom", request=req)
    _patch_client_with(monkeypatch, _BoomTransport())
    r = mirror.publish(_sth(), tenant_id="t")
    assert r["success"] is False
    assert "ConnectError" in r["error_message"]


# ── Rekor backend ───────────────────────────────────────────────────

def test_rekor_rejects_hmac_sth(monkeypatch) -> None:
    """HMAC STHs have no public counterpart — Rekor can't verify.
    Must refuse with a clear, structured error rather than fall back
    to a different scheme silently."""
    monkeypatch.setenv(
        "HALDIR_TRANSPARENCY_MIRROR",
        "rekor:https://rekor.sigstore.dev/api/v1/log/entries",
    )
    hmac_sth = _sth(algorithm="HMAC-SHA256-over-canonical-sth",
                     public_key="")
    r = mirror.publish(hmac_sth, tenant_id="t")
    assert r["success"] is False
    assert "Ed25519" in r["error_message"]


def test_rekor_builds_hashedrekord(monkeypatch) -> None:
    """When Rekor succeeds, Haldir records the UUID the log returned.
    Verify we construct the hashedrekord shape Rekor expects
    (apiVersion, kind, spec.signature.content, spec.data.hash)."""
    monkeypatch.setenv(
        "HALDIR_TRANSPARENCY_MIRROR",
        "rekor:https://rekor.sigstore.dev/api/v1/log/entries",
    )
    # Use a real Ed25519 keypair so the PEM encoding path runs.
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    sig_raw = priv.sign(b"dummy")

    sth = _sth(
        public_key=pub_raw.hex(),
        signature=sig_raw.hex(),
    )

    fake = _FakeTransport(
        status=201,
        body={"24296fb24b8ad77a": {
            "logIndex": 9000001,
            "integratedTime": 1_700_000_001,
        }},
    )
    _patch_client_with(monkeypatch, fake)

    r = mirror.publish(sth, tenant_id="t")
    assert r["success"] is True
    assert r["backend"] == "rekor"
    assert r["receipt_id"] == "24296fb24b8ad77a"
    assert r["log_index"] == 9000001

    # Verify the body Rekor received is a well-formed hashedrekord.
    assert fake.captured is not None
    body = json.loads(bytes(fake.captured.content))
    assert body["apiVersion"] == "0.0.1"
    assert body["kind"] == "hashedrekord"
    assert body["spec"]["data"]["hash"]["algorithm"] == "sha256"
    # Public key must be PEM (starts with base64-encoded
    # "-----BEGIN PUBLIC KEY-----")
    import base64
    pk_b64 = body["spec"]["signature"]["publicKey"]["content"]
    pk_pem = base64.b64decode(pk_b64).decode()
    assert pk_pem.startswith("-----BEGIN PUBLIC KEY-----"), (
        "Rekor requires the public key as PEM SubjectPublicKeyInfo"
    )


def test_rekor_http_rejection_surfaces_cleanly(monkeypatch) -> None:
    monkeypatch.setenv(
        "HALDIR_TRANSPARENCY_MIRROR", "rekor:https://rekor.example/log",
    )
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.generate()
    sth = _sth(
        public_key=priv.public_key().public_bytes_raw().hex(),
        signature=priv.sign(b"x").hex(),
    )
    fake = _FakeTransport(status=409, body={"code": 409, "message": "dup"})
    _patch_client_with(monkeypatch, fake)
    r = mirror.publish(sth, tenant_id="t")
    assert r["success"] is False
    assert "409" in r["error_message"]


# ── DB persistence ─────────────────────────────────────────────────

def test_record_and_list_receipts_round_trip(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    receipt = {
        "backend":       "file:/tmp/x",
        "success":       True,
        "receipt_id":    "abc123",
        "log_index":     42,
        "receipt_json":  {"path": "/tmp/x", "offset": 42},
        "error_message": "",
        "mirrored_at":   1_700_000_000.5,
    }
    mirror.record_receipt(db, "tnt", 5, receipt)
    out = mirror.list_receipts(db, "tnt")
    assert len(out) == 1
    r = out[0]
    assert r["backend"] == "file:/tmp/x"
    assert r["receipt_id"] == "abc123"
    assert r["log_index"] == 42
    assert r["success"] is True
    assert r["receipt_json"]["offset"] == 42


def test_list_receipts_tenant_scoped(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    for tenant in ("a", "b"):
        mirror.record_receipt(db, tenant, 1, {
            "backend": "rekor", "success": True, "mirrored_at": 1.0,
        })
    a = mirror.list_receipts(db, "a")
    b = mirror.list_receipts(db, "b")
    assert len(a) == 1 and a[0]["tenant_id"] == "a"
    assert len(b) == 1 and b[0]["tenant_id"] == "b"


def test_list_receipts_tree_size_filter(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    for size in (1, 2, 3):
        mirror.record_receipt(db, "t", size, {
            "backend": "file:x", "success": True, "mirrored_at": float(size),
        })
    only_two = mirror.list_receipts(db, "t", tree_size=2)
    assert len(only_two) == 1
    assert only_two[0]["tree_size"] == 2


# ── Hook contract ──────────────────────────────────────────────────

def test_mirror_and_record_persists_receipt(tmp_path, monkeypatch) -> None:
    db = _isolated_db(tmp_path)
    path = tmp_path / "ext.jsonl"
    monkeypatch.setenv("HALDIR_TRANSPARENCY_MIRROR", f"file:{path}")
    r = mirror.mirror_and_record(db, "t", _sth(tree_size=9))
    assert r["success"] is True
    # Receipt is in the DB.
    rows = mirror.list_receipts(db, "t")
    assert len(rows) == 1
    assert rows[0]["tree_size"] == 9


def test_get_tree_head_records_mirror_receipt(tmp_path, monkeypatch) -> None:
    """Integration: a get_tree_head call on a seeded tenant writes a
    mirror receipt to the DB when the mirror is configured."""
    import haldir_audit_tree
    from haldir_db import get_db

    db = _isolated_db(tmp_path)
    # Give the tenant one audit row so the tree isn't empty.
    conn = get_db(db)
    conn.execute(
        "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, "
        "action, tool, details, cost_usd, timestamp, flagged, prev_hash, "
        "entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?)",
        ("e-1", "tnt-hook", "s", "a", "act", "tool", "{}", 0.0, 100.0, "h"),
    )
    conn.commit()
    conn.close()

    # Enable Ed25519 + mirror via a local file.
    path = tmp_path / "mirror.jsonl"
    monkeypatch.setenv("HALDIR_TREE_SIGNING_KEY_ED25519_SEED", "hook-test")
    monkeypatch.setenv("HALDIR_TRANSPARENCY_MIRROR", f"file:{path}")

    sth = haldir_audit_tree.get_tree_head(db, "tnt-hook")
    assert sth["algorithm"].startswith("Ed25519")

    rows = mirror.list_receipts(db, "tnt-hook")
    assert len(rows) == 1
    assert rows[0]["success"] is True
    assert rows[0]["tree_size"] == sth["tree_size"]


def test_get_tree_head_survives_mirror_failure(tmp_path, monkeypatch) -> None:
    """Load-bearing invariant: if the mirror backend is broken, the
    STH response STILL succeeds. Mirror is additive-defense, not
    on-the-hot-path."""
    import haldir_audit_tree
    from haldir_db import get_db

    db = _isolated_db(tmp_path)
    conn = get_db(db)
    conn.execute(
        "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, "
        "action, tool, details, cost_usd, timestamp, flagged, prev_hash, "
        "entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?)",
        ("e-1", "tnt-broke", "s", "a", "act", "tool", "{}", 0.0, 100.0, "h"),
    )
    conn.commit()
    conn.close()

    # Backend that will ConnectError.
    monkeypatch.setenv("HALDIR_TRANSPARENCY_MIRROR",
                        "http://broken-mirror.invalid/path")

    class _BoomTransport(httpx.BaseTransport):
        def handle_request(self, req):
            raise httpx.ConnectError("boom", request=req)
    _patch_client_with(monkeypatch, _BoomTransport())

    sth = haldir_audit_tree.get_tree_head(db, "tnt-broke")
    # STH was returned successfully.
    assert sth["tree_size"] >= 1
    # And a FAILURE receipt was recorded so an operator dashboard can
    # surface mirror degradation.
    rows = mirror.list_receipts(db, "tnt-broke")
    assert len(rows) == 1
    assert rows[0]["success"] is False
    assert "ConnectError" in rows[0]["error_message"]


# ── HTTP endpoint integration ──────────────────────────────────────

def test_endpoint_lists_receipts(haldir_client, bootstrap_key,
                                  monkeypatch, tmp_path) -> None:
    """Live HTTP check: GET /v1/audit/sth-log/mirror/receipts returns
    the expected shape, tenant-scoped, after a mirrored STH is
    produced via get_tree_head."""
    import api, haldir_audit_tree, haldir_migrate
    # The shared test DB was bootstrapped long ago; make sure
    # migration 007 (sth_mirror_receipts) has been applied before we
    # try to write to it.
    haldir_migrate.apply_pending(api.DB_PATH)
    path = tmp_path / "live.jsonl"
    monkeypatch.setenv("HALDIR_TREE_SIGNING_KEY_ED25519_SEED", "ep-test")
    monkeypatch.setenv("HALDIR_TRANSPARENCY_MIRROR", f"file:{path}")

    # Compute a tree head so a mirror receipt is written.
    import hashlib
    from haldir_db import get_db
    kh = hashlib.sha256(bootstrap_key.encode()).hexdigest()
    conn = get_db(api.DB_PATH)
    row = conn.execute(
        "SELECT tenant_id FROM api_keys WHERE key_hash = ?", (kh,),
    ).fetchone()
    conn.close()
    tenant = row["tenant_id"]
    haldir_audit_tree.get_tree_head(api.DB_PATH, tenant)

    r = haldir_client.get(
        "/v1/audit/sth-log/mirror/receipts",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert "receipts" in body
    assert body["count"] >= 1
    # Every receipt has the contract shape.
    for rec in body["receipts"]:
        for key in ("tree_size", "backend", "receipt_id", "log_index",
                     "mirrored_at", "success"):
            assert key in rec


def test_endpoint_requires_audit_read_scope(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "no-audit-mirror", "scopes": ["sessions:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    narrow = r.get_json()["key"]
    r2 = haldir_client.get(
        "/v1/audit/sth-log/mirror/receipts",
        headers={"Authorization": f"Bearer {narrow}"},
    )
    assert r2.status_code == 403
