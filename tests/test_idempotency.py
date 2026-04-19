"""
Tests for haldir_idempotency — retry-safe POST semantics.

Covers:
  - Body hashing is canonical (key order doesn't affect hash)
  - First call misses the cache (returns None → handler executes)
  - Second call with same (tenant, key, endpoint, body) hits the cache
  - Same key with different body raises IdempotencyMismatch
  - Tenant isolation (alice's key is not accessible to bob)
  - Endpoint isolation (same key for /audit and /payments is separate)
  - Retention window: expired rows are treated as misses
  - prune_expired removes old rows, leaves fresh ones
  - Concurrent INSERT-OR-REPLACE races converge to one row

Run: python -m pytest tests/test_idempotency.py -v
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_idempotency import (
    CachedResponse,
    IdempotencyMismatch,
    _hash_body,
    init_schema,
    lookup,
    prune_expired,
    store,
)


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def conn():
    """An in-memory SQLite DB with the schema initialised."""
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    init_schema(c)
    yield c
    c.close()


# ── Body hashing ─────────────────────────────────────────────────────────

def test_body_hash_is_canonical() -> None:
    """Dicts with the same content but different insertion orders hash
    identically — important so clients re-serialising after modification
    don't accidentally trigger IdempotencyMismatch."""
    a = {"session_id": "s1", "tool": "stripe", "cost_usd": 1.50}
    b = {"cost_usd": 1.50, "tool": "stripe", "session_id": "s1"}
    assert _hash_body(a) == _hash_body(b)


def test_body_hash_changes_with_content() -> None:
    a = {"session_id": "s1", "cost_usd": 1.00}
    b = {"session_id": "s1", "cost_usd": 2.00}
    assert _hash_body(a) != _hash_body(b)


def test_body_hash_produces_64_hex_chars() -> None:
    # SHA-256 hex = 64 chars
    h = _hash_body({"a": 1, "b": 2})
    assert len(h) == 64
    int(h, 16)  # valid hex


# ── Miss path ────────────────────────────────────────────────────────────

def test_lookup_returns_none_when_key_missing(conn) -> None:
    result = lookup(conn, tenant_id="t", key="k", endpoint="/v1/audit",
                    body={"a": 1})
    assert result is None


# ── Hit path ─────────────────────────────────────────────────────────────

def test_store_then_lookup_returns_cached_response(conn) -> None:
    body = {"session_id": "s1", "tool": "stripe", "cost_usd": 1.0}
    response = {"entry_id": "aud_x", "logged": True, "flagged": False}

    store(conn, tenant_id="t", key="k1", endpoint="/v1/audit",
          body=body, response=response, status_code=200)

    hit = lookup(conn, tenant_id="t", key="k1", endpoint="/v1/audit", body=body)
    assert isinstance(hit, CachedResponse)
    assert hit.status == 200
    assert hit.body == response


def test_cached_response_survives_body_key_reorder(conn) -> None:
    """Same logical body, different key order at retrieval time — still hits."""
    body_first = {"session_id": "s1", "tool": "stripe", "cost_usd": 1.0}
    body_retry = {"cost_usd": 1.0, "tool": "stripe", "session_id": "s1"}
    resp = {"entry_id": "aud_x"}

    store(conn, tenant_id="t", key="k", endpoint="/v1/audit",
          body=body_first, response=resp)

    hit = lookup(conn, tenant_id="t", key="k", endpoint="/v1/audit",
                 body=body_retry)
    assert hit is not None
    assert hit.body == resp


# ── Mismatch path ────────────────────────────────────────────────────────

def test_same_key_different_body_raises_mismatch(conn) -> None:
    """Same idempotency key, different request body = programming error."""
    store(conn, tenant_id="t", key="k", endpoint="/v1/audit",
          body={"amount": 100}, response={"ok": True})

    with pytest.raises(IdempotencyMismatch, match="different request body"):
        lookup(conn, tenant_id="t", key="k", endpoint="/v1/audit",
               body={"amount": 200})


# ── Isolation ────────────────────────────────────────────────────────────

def test_tenant_isolation(conn) -> None:
    """Alice's idempotency key must not be visible to Bob."""
    body = {"amount": 100}
    store(conn, tenant_id="alice", key="k", endpoint="/v1/audit",
          body=body, response={"alice-saw-this": True})

    # Bob, same key, same endpoint, same body — but different tenant
    result = lookup(conn, tenant_id="bob", key="k", endpoint="/v1/audit", body=body)
    assert result is None


def test_endpoint_isolation(conn) -> None:
    """The same key on two different endpoints is two different rows."""
    body = {"amount": 100}
    store(conn, tenant_id="t", key="k", endpoint="/v1/audit",
          body=body, response={"from": "audit"})

    # Same key on /payments — should miss
    result = lookup(conn, tenant_id="t", key="k", endpoint="/v1/payments/authorize",
                    body=body)
    assert result is None


# ── Retention ────────────────────────────────────────────────────────────

def test_expired_entries_are_treated_as_miss(conn) -> None:
    body = {"amount": 100}
    response = {"entry_id": "aud_old"}

    # Store with a synthetic "now" of 2 days ago
    two_days_ago = time.time() - 172800
    store(conn, tenant_id="t", key="k", endpoint="/v1/audit",
          body=body, response=response, now=two_days_ago)

    # Default retention is 24h, so a lookup now should see no match
    hit = lookup(conn, tenant_id="t", key="k", endpoint="/v1/audit", body=body)
    assert hit is None


def test_expired_entries_mismatch_check_is_suppressed(conn) -> None:
    """Even if the expired row had a different body hash, lookup still
    returns None (doesn't raise IdempotencyMismatch) — the row is
    effectively gone."""
    two_days_ago = time.time() - 172800
    store(conn, tenant_id="t", key="k", endpoint="/v1/audit",
          body={"old": "body"}, response={"old": True}, now=two_days_ago)

    result = lookup(conn, tenant_id="t", key="k", endpoint="/v1/audit",
                    body={"new": "body"})
    assert result is None


def test_prune_expired_removes_old_rows(conn) -> None:
    two_days_ago = time.time() - 172800
    one_hour_ago = time.time() - 3600

    store(conn, tenant_id="t", key="old", endpoint="/v1/audit",
          body={"x": 1}, response={}, now=two_days_ago)
    store(conn, tenant_id="t", key="fresh", endpoint="/v1/audit",
          body={"x": 2}, response={}, now=one_hour_ago)

    pruned = prune_expired(conn)
    assert pruned == 1

    # Fresh row survives
    hit = lookup(conn, tenant_id="t", key="fresh", endpoint="/v1/audit",
                 body={"x": 2})
    assert hit is not None


# ── Concurrency ──────────────────────────────────────────────────────────

def test_concurrent_stores_same_key_converge_to_one_row(tmp_path) -> None:
    """Two threads racing on the same key end up with one row in the DB;
    both callers see the same cached response on the next lookup.

    Uses a file-backed SQLite so each thread opens its own connection —
    this matches production where each request handler gets a fresh
    connection from the pool (see haldir_db.get_db)."""
    db_path = str(tmp_path / "idempotency.db")
    setup = sqlite3.connect(db_path)
    setup.row_factory = sqlite3.Row
    init_schema(setup)
    setup.close()

    body = {"amount": 100}
    results: list[Exception] = []

    def _worker(key_suffix: str) -> None:
        c = sqlite3.connect(db_path, timeout=5)
        c.row_factory = sqlite3.Row
        try:
            store(c, tenant_id="t", key="shared-key", endpoint="/v1/audit",
                  body=body, response={"winner": key_suffix})
            c.commit()
        except Exception as e:  # pragma: no cover
            results.append(e)
        finally:
            c.close()

    t1 = threading.Thread(target=_worker, args=("a",))
    t2 = threading.Thread(target=_worker, args=("b",))
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert len(results) == 0, f"stores raised: {results}"

    # Verify convergence: one row, both threads see the same response
    verify = sqlite3.connect(db_path)
    verify.row_factory = sqlite3.Row
    count = verify.execute(
        "SELECT COUNT(*) FROM idempotency_keys WHERE key = 'shared-key'"
    ).fetchone()[0]
    assert count == 1

    hit = lookup(verify, tenant_id="t", key="shared-key",
                 endpoint="/v1/audit", body=body)
    assert hit is not None
    assert hit.body["winner"] in ("a", "b")
    verify.close()


# ── Schema migration is idempotent ───────────────────────────────────────

def test_init_schema_is_idempotent(conn) -> None:
    # Already initialized in the fixture — calling again should not raise
    init_schema(conn)
    init_schema(conn)
    # Prove the table still works
    store(conn, tenant_id="t", key="k", endpoint="/v1/audit",
          body={"a": 1}, response={"ok": True})
    assert lookup(conn, tenant_id="t", key="k", endpoint="/v1/audit", body={"a": 1}) is not None
