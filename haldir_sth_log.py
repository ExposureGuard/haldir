"""
Haldir self-published Signed Tree Head log — anti-equivocation layer.

What this is:

  Every Signed Tree Head Haldir produces (via haldir_audit_tree.
  get_tree_head) is recorded to a per-tenant append-only log keyed on
  tree_size. The log itself is publicly queryable by anyone holding
  the tenant's API key. Combined with the existing RFC 6962 inclusion
  + consistency proofs, this closes the "who watches the watchman"
  loop.

What it defends against:

  1. **Silent rewrite.** If Haldir ever changed an old STH to fit
     a different current state, an auditor with the old STH pinned
     would see the verify endpoint return `verified: false` —
     instantly provable equivocation.

  2. **Backdated state.** The recorded_at timestamp + monotonic
     tree_size sequence make it impossible to insert a fake
     "earlier" STH after the fact without breaking the chain of
     observed sizes.

  3. **Differential disclosure.** Two auditors holding different
     STHs for the same tree_size have a cryptographic proof of
     server misbehaviour — the keyed PK guarantees only one row
     per (tenant, tree_size) ever exists, so two distinct
     signatures for the same key prove the operator equivocated.

What it does NOT (yet) defend against:

  - **Coordinated wipe.** If Haldir's own DB is compromised AND
    every external mirror is taken down simultaneously, the log
    can be erased. Phase 2 mirrors STHs to an external monitor
    (Sigstore / Rekor / on-chain via EAS) so even DB compromise
    is detectable. v2 of this module.

  - **Refusal to publish.** A server that simply refuses to serve
    the sth-log endpoint can't be forced to. But that itself is a
    detectable defect — an auditor's "Haldir doesn't serve its
    own STH log" is a red flag worth flagging.

Operations:

  record(tenant_id, sth)            persist; idempotent on (tenant, size)
  list(tenant_id, since, limit)     ordered history since a tree size
  count(tenant_id)                  number of distinct STHs recorded
  earliest(tenant_id) / latest()    bookends
  verify_against_pinned(...)        an auditor's pinned STH still matches

References:
  RFC 6962 §5 — STH operations + monitor responsibilities
  CT log monitor architecture: certificate-transparency.org/monitors
"""

from __future__ import annotations

import time
from typing import Any


# ── Recording ──────────────────────────────────────────────────────

def record(db_path: str, tenant_id: str, sth: dict[str, Any]) -> bool:
    """Persist an STH if (tenant_id, tree_size) is new for this log.

    Returns True if a new row was inserted, False if (tenant, size)
    was already recorded — in which case the existing row is kept and
    we silently no-op. Two STHs for the same (tenant, size) MUST be
    identical in their signed bytes; if they aren't, that's
    equivocation, but our INSERT-OR-IGNORE strategy keeps the FIRST
    observation as canonical (which is the conservative choice — a
    later equivocation is detected by `verify_against_pinned`).

    Designed to be called inline from `get_tree_head`. Best-effort:
    any exception here is swallowed and logged so a transient DB
    issue can't block a tree-head response.
    """
    try:
        from haldir_db import get_db
    except Exception:
        return False

    tree_size = int(sth.get("tree_size", 0))
    if tree_size < 0:
        return False

    conn = get_db(db_path)
    try:
        # SQLite + Postgres both support ON CONFLICT DO NOTHING since
        # SQLite 3.24 / Postgres 9.5. Either way, the (tenant_id,
        # tree_size) PK enforces idempotency at the schema layer; the
        # ON CONFLICT just turns "duplicate key" from an error into a
        # no-op so the caller doesn't have to catch.
        cur = conn.execute(
            "INSERT INTO sth_log "
            "(tenant_id, tree_size, root_hash, algorithm, signature, "
            " signed_at, key_id, public_key, recorded_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (tenant_id, tree_size) DO NOTHING",
            (
                tenant_id,
                tree_size,
                str(sth.get("root_hash", "")),
                str(sth.get("algorithm", "")),
                str(sth.get("signature", "")),
                int(sth.get("signed_at", 0)),
                str(sth.get("key_id", "")),
                str(sth.get("public_key", "")),
                time.time(),
            ),
        )
        conn.commit()
        # Some DB drivers report rowcount == -1 on ON CONFLICT no-ops;
        # treat that as "not new" so callers don't double-count.
        new = cur.rowcount == 1
        return new
    except Exception:
        # Best-effort. Never crash get_tree_head over an STH-log error.
        return False
    finally:
        conn.close()


# ── Reading ────────────────────────────────────────────────────────

def list(  # noqa: A001  (shadowing builtin is deliberate, scoped to the module)
    db_path: str,
    tenant_id: str,
    since_tree_size: int = 0,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Return STHs for a tenant in ascending tree_size order.

    `since_tree_size`: exclusive lower bound. Pass the last tree_size
    a caller already has to fetch only newer entries. Use 0 to start
    from the beginning.
    `limit`: hard cap on rows returned (default 1000).

    Each row is the same shape an STH produced by sign_sth has, plus
    a `recorded_at` float (server-side wall-clock when the STH was
    first observed by the log). Useful for downstream timing checks.
    """
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        rows = conn.execute(
            "SELECT tenant_id, tree_size, root_hash, algorithm, signature, "
            "signed_at, key_id, public_key, recorded_at "
            "FROM sth_log WHERE tenant_id = ? AND tree_size > ? "
            "ORDER BY tree_size ASC LIMIT ?",
            (tenant_id, int(since_tree_size), int(limit)),
        ).fetchall()
    finally:
        conn.close()
    return [_row_to_dict(r) for r in rows]


def count(db_path: str, tenant_id: str) -> int:
    """Number of distinct STHs recorded for a tenant. O(1) via index."""
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM sth_log WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]
    finally:
        conn.close()
    return int(n)


def latest(db_path: str, tenant_id: str) -> dict[str, Any] | None:
    """Most recently recorded STH for a tenant, or None if log is empty."""
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        row = conn.execute(
            "SELECT tenant_id, tree_size, root_hash, algorithm, signature, "
            "signed_at, key_id, public_key, recorded_at "
            "FROM sth_log WHERE tenant_id = ? "
            "ORDER BY tree_size DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
    finally:
        conn.close()
    return _row_to_dict(row) if row else None


def earliest(db_path: str, tenant_id: str) -> dict[str, Any] | None:
    """Oldest recorded STH. Useful for an auditor checking how far
    back the log goes — their pinned STH must be at least this old
    for verification to be possible."""
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        row = conn.execute(
            "SELECT tenant_id, tree_size, root_hash, algorithm, signature, "
            "signed_at, key_id, public_key, recorded_at "
            "FROM sth_log WHERE tenant_id = ? "
            "ORDER BY tree_size ASC LIMIT 1",
            (tenant_id,),
        ).fetchone()
    finally:
        conn.close()
    return _row_to_dict(row) if row else None


# ── Verification ────────────────────────────────────────────────────

def verify_against_pinned(
    db_path: str,
    tenant_id: str,
    pinned_tree_size: int,
    pinned_root_hash: str,
) -> dict[str, Any]:
    """Verify that an auditor's pinned (tree_size, root_hash) matches
    what we recorded for that tree_size.

    Three possible outcomes:

      1. **Match.** The recorded row's root_hash == pinned root.
         Returns `{verified: True, ...}`. Combined with a fresh
         consistency proof from the live tree, the auditor can
         conclude the current log is an append-only extension of
         what they pinned.

      2. **Mismatch.** Same tree_size, different root. This is
         CRYPTOGRAPHIC PROOF OF EQUIVOCATION — Haldir signed two
         different STHs for the same tree size at some point.
         Returns `{verified: False, reason: 'equivocation', ...}`
         with both root values for the auditor to disclose.

      3. **Out of range.** No row at the pinned tree_size — either
         it predates our log retention (earliest() returns
         something larger) OR the pinned STH was never genuinely
         issued by Haldir (forgery / wrong tenant). Returns
         `{verified: False, reason: 'not_in_log', ...}` with
         enough context for the auditor to disambiguate.
    """
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        row = conn.execute(
            "SELECT tenant_id, tree_size, root_hash, algorithm, signature, "
            "signed_at, key_id, public_key, recorded_at "
            "FROM sth_log WHERE tenant_id = ? AND tree_size = ?",
            (tenant_id, int(pinned_tree_size)),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        # Disambiguate: is the pinned size before our retention or
        # ahead of our current state?
        latest_sth = latest(db_path, tenant_id)
        earliest_sth = earliest(db_path, tenant_id)
        if latest_sth is None:
            note = "log is empty for this tenant"
        elif int(pinned_tree_size) < int(earliest_sth["tree_size"]):
            note = (
                f"pinned tree_size {pinned_tree_size} predates the log "
                f"(earliest recorded is {earliest_sth['tree_size']})"
            )
        elif int(pinned_tree_size) > int(latest_sth["tree_size"]):
            note = (
                f"pinned tree_size {pinned_tree_size} is ahead of the "
                f"current log (latest recorded is "
                f"{latest_sth['tree_size']}) — pinned STH may be a forgery"
            )
        else:
            # Possible if the log has gaps (which the schema prevents
            # at PK level, but not for tree_sizes that simply weren't
            # observed at all because get_tree_head wasn't called at
            # those sizes).
            note = (
                f"no STH recorded at tree_size {pinned_tree_size} — "
                "this size was never queried via get_tree_head"
            )
        return {
            "verified":      False,
            "reason":        "not_in_log",
            "note":          note,
            "pinned_tree_size": int(pinned_tree_size),
            "pinned_root_hash": pinned_root_hash,
        }

    recorded = _row_to_dict(row)
    if recorded["root_hash"] == pinned_root_hash:
        return {
            "verified":          True,
            "reason":            "match",
            "pinned_tree_size":  int(pinned_tree_size),
            "pinned_root_hash":  pinned_root_hash,
            "recorded":          recorded,
        }
    return {
        "verified":          False,
        "reason":            "equivocation",
        "note": (
            "Recorded STH for this tree_size has a different root_hash "
            "than the auditor pinned. This is cryptographic proof that "
            "two different STHs were issued for the same tree size — "
            "publish both for verification."
        ),
        "pinned_tree_size":   int(pinned_tree_size),
        "pinned_root_hash":   pinned_root_hash,
        "recorded_root_hash": recorded["root_hash"],
        "recorded":           recorded,
    }


# ── Helpers ────────────────────────────────────────────────────────

def _row_to_dict(row: Any) -> dict[str, Any]:
    """SQLite3 Row + Postgres dict-row both support `row[k]`. Convert
    to a stable JSON-safe dict."""
    return {
        "tenant_id":   row["tenant_id"],
        "tree_size":   int(row["tree_size"]),
        "root_hash":   row["root_hash"],
        "algorithm":   row["algorithm"],
        "signature":   row["signature"],
        "signed_at":   int(row["signed_at"]),
        "key_id":      row["key_id"],
        "public_key":  row["public_key"],
        "recorded_at": float(row["recorded_at"]),
    }
