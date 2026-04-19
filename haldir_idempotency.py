"""
Haldir Idempotency — retry-safe POST semantics.

When a caller supplies an `Idempotency-Key` header on a POST request, the
same key + same tenant + same endpoint returning within the retention
window (default 24 hours) will return the ORIGINAL response rather than
re-executing the handler. This is what Stripe, Square, AWS, and every
serious financial API does for operations that can't be safely retried.

Why it matters:

  - Network hiccups: the client's `POST /v1/audit` times out after the
    server wrote the entry; the client retries; the second write would
    create a duplicate audit entry (breaking the hash chain's 1-to-1
    correspondence with agent actions).

  - `POST /v1/payments/authorize`: a retry would double-charge the
    session's spend cap.

With idempotency keys the client can safely retry any number of times
and get the same result as the first successful attempt.

## API contract

Clients supply the key via the `Idempotency-Key` HTTP header. The key
should be:
  - UUID v4, or any other high-entropy string
  - Generated ONCE per logical operation and reused across retries
  - Different per distinct logical operation

If the same key is reused with a DIFFERENT request body, the helper
returns an IdempotencyMismatch sentinel so the handler can return
HTTP 422 Unprocessable — that's a programming error in the client.

## Concurrency

Two simultaneous requests with the same key race on INSERT. The second
loser catches the constraint violation, reads the stored response, and
returns it. The first winner runs the handler and stores its response.
Both callers see the same response.

## Retention

Rows older than `RETENTION_SECONDS` (default 86400 = 24h) are invisible
to `lookup()` and will be cleaned up by `prune_expired()` which a cron
or scheduled job can run periodically.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Optional


RETENTION_SECONDS = 86400   # 24 hours; balances retry windows against storage


class IdempotencyMismatch(Exception):
    """Raised when the same idempotency key is reused with a different body.

    The REST layer should translate this to `HTTP 422 Unprocessable`.
    """


@dataclass
class CachedResponse:
    status: int
    body: dict[str, Any]


def _hash_body(body: dict[str, Any]) -> str:
    """Canonical hash of a request body.

    Uses sort_keys so dict insertion order doesn't influence the hash. Does
    not hash the idempotency key itself (the body is what determines
    "logical operation"; the key is just the identifier for this attempt).
    """
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def init_schema(conn: Any) -> None:
    """Idempotent schema migration. Safe to call multiple times."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS idempotency_keys (
            tenant_id   TEXT    NOT NULL,
            key         TEXT    NOT NULL,
            endpoint    TEXT    NOT NULL,
            body_hash   TEXT    NOT NULL,
            response    TEXT    NOT NULL,
            status_code INTEGER NOT NULL,
            created_at  REAL    NOT NULL,
            PRIMARY KEY (tenant_id, key, endpoint)
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_idempotency_created "
        "ON idempotency_keys(created_at)"
    )


def lookup(
    conn: Any,
    tenant_id: str,
    key: str,
    endpoint: str,
    body: dict[str, Any],
    *,
    retention_seconds: int = RETENTION_SECONDS,
    now: Optional[float] = None,
) -> Optional[CachedResponse]:
    """Check if this (tenant, key, endpoint) has a cached response.

    Returns:
        CachedResponse if a matching row exists within the retention window
        AND the body hash matches — the caller should return it verbatim
        instead of executing the handler.

        None if no row exists — caller proceeds with the handler and must
        call `store()` with the final response.

    Raises:
        IdempotencyMismatch if a row exists but the body hash differs —
        the caller SHOULD return HTTP 422. Same key, different body is
        a programming error in the client.
    """
    current = now if now is not None else time.time()
    cutoff = current - retention_seconds

    row = conn.execute(
        "SELECT body_hash, response, status_code, created_at "
        "FROM idempotency_keys "
        "WHERE tenant_id = ? AND key = ? AND endpoint = ?",
        (tenant_id, key, endpoint),
    ).fetchone()

    if not row:
        return None

    # Expired — treat as miss; caller will overwrite on the next store.
    if row["created_at"] < cutoff:
        return None

    # Key reused with different body — programming error
    incoming_hash = _hash_body(body)
    if row["body_hash"] != incoming_hash:
        raise IdempotencyMismatch(
            f"Idempotency-Key {key!r} was previously used with a different "
            f"request body on {endpoint!r}. Use a fresh key or send the "
            f"identical body."
        )

    return CachedResponse(
        status=int(row["status_code"]),
        body=json.loads(row["response"]),
    )


def store(
    conn: Any,
    tenant_id: str,
    key: str,
    endpoint: str,
    body: dict[str, Any],
    response: dict[str, Any],
    status_code: int = 200,
    *,
    now: Optional[float] = None,
) -> None:
    """Cache a response against its idempotency key.

    Uses INSERT OR REPLACE so two concurrent callers racing on the same
    key end up with the same final row (the second writer wins; both
    callers see the same cached response on subsequent retries).
    """
    current = now if now is not None else time.time()
    conn.execute(
        "INSERT OR REPLACE INTO idempotency_keys "
        "(tenant_id, key, endpoint, body_hash, response, status_code, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            tenant_id, key, endpoint,
            _hash_body(body),
            json.dumps(response, sort_keys=True),
            status_code,
            current,
        ),
    )


def prune_expired(
    conn: Any,
    *,
    retention_seconds: int = RETENTION_SECONDS,
    now: Optional[float] = None,
) -> int:
    """Delete idempotency rows older than the retention window.

    Returns:
        Number of rows deleted. Call from a scheduled job or cron.
    """
    current = now if now is not None else time.time()
    cutoff = current - retention_seconds
    cursor = conn.execute(
        "DELETE FROM idempotency_keys WHERE created_at < ?",
        (cutoff,),
    )
    return int(cursor.rowcount)
