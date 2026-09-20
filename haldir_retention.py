"""
Audit retention windows, and pruning that stays provable.

Two things every enterprise buyer asks, and Haldir could not answer either:

  "How long do you keep audit data?"   — forever, with no way to change it.
  "Can you delete it on request?"      — no, and there was no mechanism coming.

For a tenant with a data-deletion obligation the second is not a missing
feature, it is a compliance failure. For everyone else the audit log is
append-only and unbounded, growing at whatever rate their agents work.

── The problem ─────────────────────────────────────────────────────────

The audit log is a hash chain: each entry commits to the hash of the one
before it, and `verify_chain` walks from the oldest entry forward starting
from an empty `prev_hash`. Delete the oldest rows and the new-oldest entry
points at a hash that no longer exists — so a naive prune turns a working
audit trail into one that fails verification. That is a strictly worse
outcome than never pruning.

── The approach ────────────────────────────────────────────────────────

Same shape Certificate Transparency uses for log sharding: you cannot keep
everything forever, so you keep a signed commitment to what you dropped.

Before deleting anything, this takes a Signed Tree Head over the log as it
stands and records the hash of the newest entry being removed. That hash is
the link across the boundary — verification of the survivors starts from it
instead of from empty — and the STH is the commitment to the removed prefix.

So the honest answer to an auditor becomes "entries before this point were
deleted under a retention policy, and here is the signed Merkle root they
produced at the time", which is a complete answer. A silently shorter log
would not be.

If the tree head cannot be produced, the prune does not happen. Pruning
without a commitment is the exact thing this module exists to prevent.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

# Sentinel: "use the tenant's configured policy". Distinct from 0, which
# means "keep forever, prune nothing".
USE_POLICY = -1

CHECKPOINT_PREFIX = "ckpt_"


def _conn(db_path: str) -> Any:
    from haldir_db import get_db
    return get_db(db_path)


# ── Policy ───────────────────────────────────────────────────────────

def get_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    """The tenant's retention window. Absent means keep forever."""
    conn = _conn(db_path)
    try:
        row = conn.execute(
            "SELECT retain_days, updated_at, updated_by FROM audit_retention "
            "WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return {"tenant_id": tenant_id, "retain_days": 0, "updated_at": None,
                "updated_by": "", "configured": False}
    return {
        "tenant_id":   tenant_id,
        "retain_days": int(row["retain_days"]),
        "updated_at":  float(row["updated_at"]),
        "updated_by":  row["updated_by"] or "",
        "configured":  True,
    }


def set_policy(db_path: str, tenant_id: str, retain_days: int,
               updated_by: str = "") -> dict[str, Any]:
    """Set the window. 0 means keep forever, and is how you turn pruning off."""
    if retain_days < 0:
        raise ValueError("retain_days must be >= 0 (0 keeps everything)")
    now = time.time()
    conn = _conn(db_path)
    try:
        # Bare column names on the left of SET, `excluded.` on the right.
        # SQLite rejects a table-qualified *target* column ("near .: syntax
        # error") though it accepts qualification inside the expression, and
        # Postgres accepts both — so this spelling is the one that works on
        # both engines without a translation branch.
        conn.execute(
            "INSERT INTO audit_retention (tenant_id, retain_days, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(tenant_id) DO UPDATE SET "
            "retain_days = excluded.retain_days, "
            "updated_at  = excluded.updated_at, "
            "updated_by  = excluded.updated_by",
            (tenant_id, int(retain_days), now, updated_by),
        )
        conn.commit()
    finally:
        conn.close()
    return get_policy(db_path, tenant_id)


# ── What a prune would do ────────────────────────────────────────────

def preview(db_path: str, tenant_id: str, retain_days: int = USE_POLICY) -> dict[str, Any]:
    """Report what a prune would remove, without removing it.

    Worth calling before the real thing: pruning is deliberately not
    reversible, so the caller should see the size of it first.
    """
    if retain_days == USE_POLICY:
        retain_days = get_policy(db_path, tenant_id)["retain_days"]

    if retain_days <= 0:
        return {"tenant_id": tenant_id, "retain_days": retain_days,
                "would_delete": 0, "enabled": False,
                "note": "no retention window set; the audit log is kept forever"}

    cutoff = time.time() - retain_days * 86400
    conn = _conn(db_path)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ? AND timestamp < ?",
            (tenant_id, cutoff),
        ).fetchone()
        oldest = conn.execute(
            "SELECT timestamp FROM audit_log WHERE tenant_id = ? "
            "ORDER BY timestamp ASC LIMIT 1",
            (tenant_id,),
        ).fetchone()
    finally:
        conn.close()

    would_delete = int(row[0]) if row else 0
    return {
        "tenant_id":   tenant_id,
        "retain_days": retain_days,
        "cutoff":      cutoff,
        "would_delete": would_delete,
        "oldest_entry_at": float(oldest["timestamp"]) if oldest else None,
        "enabled":     True,
    }


# ── The prune ────────────────────────────────────────────────────────

def prune(db_path: str, tenant_id: str, retain_days: int = USE_POLICY,
          actor: str = "") -> dict[str, Any]:
    """Delete audit entries older than the window, keeping it verifiable.

    Deliberately not reversible, and deliberately refuses more often than it
    has to. Every refusal below is a case where pruning would leave the log
    less trustworthy than it was before.
    """
    import haldir_audit_tree

    if retain_days == USE_POLICY:
        retain_days = get_policy(db_path, tenant_id)["retain_days"]

    if retain_days <= 0:
        return {"pruned": False, "reason": "no retention window set"}

    now = time.time()
    cutoff = now - retain_days * 86400

    conn = _conn(db_path)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ? AND timestamp < ?",
            (tenant_id, cutoff),
        ).fetchone()
        entries_to_delete = int(row[0]) if row else 0
        if entries_to_delete == 0:
            return {"pruned": False, "reason": "nothing older than the window",
                    "cutoff": cutoff, "entries_deleted": 0}

        # The chain link across the boundary: the newest entry being removed.
        # Verification of the survivors starts from this hash, so without it
        # the surviving chain would appear broken.
        boundary = conn.execute(
            "SELECT entry_hash FROM audit_log WHERE tenant_id = ? AND timestamp < ? "
            "ORDER BY timestamp DESC LIMIT 1",
            (tenant_id, cutoff),
        ).fetchone()
        boundary_hash = (boundary["entry_hash"] if boundary else "") or ""
    finally:
        conn.close()

    # Commit to the log BEFORE removing anything from it. Taken first so the
    # signed root covers the entries about to be deleted — that is the whole
    # point: the commitment is to what existed, not to what is left.
    try:
        sth = haldir_audit_tree.get_tree_head(db_path, tenant_id)
    except Exception as e:
        return {"pruned": False, "reason": f"could not produce a tree head: {e}",
                "entries_deleted": 0}

    if not sth or not sth.get("root_hash"):
        return {"pruned": False, "reason": "tree head was empty; refusing to "
                                           "delete without a commitment",
                "entries_deleted": 0}

    checkpoint_id = f"{CHECKPOINT_PREFIX}{secrets.token_urlsafe(16)}"
    conn = _conn(db_path)
    try:
        conn.execute(
            "DELETE FROM audit_log WHERE tenant_id = ? AND timestamp < ?",
            (tenant_id, cutoff),
        )
        conn.execute(
            "INSERT INTO audit_checkpoints ("
            "checkpoint_id, tenant_id, pruned_before, last_pruned_entry_hash, "
            "entries_deleted, tree_size, root_hash, algorithm, signature, "
            "signed_at, key_id, public_key, created_at, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (checkpoint_id, tenant_id, cutoff, boundary_hash,
             entries_to_delete, int(sth.get("tree_size", 0)),
             sth.get("root_hash", ""), sth.get("algorithm", ""),
             sth.get("signature", ""), float(sth.get("signed_at", 0) or 0),
             sth.get("key_id", ""), sth.get("public_key", ""), now, actor),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "pruned":             True,
        "checkpoint_id":      checkpoint_id,
        "entries_deleted":    entries_to_delete,
        "pruned_before":      cutoff,
        "retain_days":        retain_days,
        # The commitment an auditor can check afterwards.
        "tree_size":          int(sth.get("tree_size", 0)),
        "root_hash":          sth.get("root_hash", ""),
        "algorithm":          sth.get("algorithm", ""),
    }


def latest_checkpoint(db_path: str, tenant_id: str) -> dict[str, Any] | None:
    """Most recent prune checkpoint, or None if the tenant has never pruned.

    `verify_chain` reads this to know where the surviving chain begins.
    """
    conn = _conn(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM audit_checkpoints WHERE tenant_id = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
    except Exception:
        return None
    finally:
        conn.close()
    if not row:
        return None
    keys = row.keys()
    return {k: row[k] for k in keys}


def list_checkpoints(db_path: str, tenant_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """Every prune a tenant has performed, newest first.

    This is itself an audit record: it says what was removed and when, which
    is the question a retention policy exists to be able to answer.
    """
    conn = _conn(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM audit_checkpoints WHERE tenant_id = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (tenant_id, limit),
        ).fetchall()
    except Exception:
        return []
    finally:
        conn.close()
    return [{k: r[k] for k in r.keys()} for r in rows]
