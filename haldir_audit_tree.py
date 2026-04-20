"""
Haldir audit-tree surface — RFC 6962 Merkle tree over the audit log.

Wraps the generic `haldir_merkle` primitives with Haldir-specific
concerns:

  - Where the leaves come from (audit_log table, tenant-scoped,
    ordered by timestamp).
  - How to turn an audit_log row into the 32 bytes we leaf-hash
    (canonical serialization — auditor can reproduce from the
    entry_id + public fields).
  - How to sign a Signed Tree Head (HMAC-SHA256 keyed from env,
    see haldir_merkle.load_signing_key_from_env).

Exported operations:

  build_sth(db_path, tenant_id)
      → (sth_dict, leaves, leaf_index_by_entry_id)

  get_tree_head(db_path, tenant_id) → dict
      STH payload ready for HTTP response.

  get_inclusion_proof(db_path, tenant_id, entry_id) → dict | None
      Proof for the specified audit entry. None if the entry isn't
      in this tenant's log.

  get_consistency_proof(db_path, tenant_id, first_size, second_size)
      → dict | None

All operations are on-demand: we don't cache tree state in the DB.
For Haldir's current scale (tens of thousands of entries per tenant)
rebuilding the tree on each request is cheap — ~millisecond per
thousand leaves. When we cross a threshold where caching matters,
the obvious move is to store precomputed internal-node hashes
keyed by (tenant, tree_size).
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

import haldir_merkle as merkle


# ── Canonical leaf bytes ──────────────────────────────────────────

def entry_leaf_bytes(row: Any) -> bytes:
    """Canonical byte encoding of an audit_log row for Merkle hashing.

    Any party holding the public audit row fields can reproduce this
    exact byte sequence. We deliberately DON'T include fields that
    could vary across DB dialects or float precision (e.g., raw
    timestamp floats → we use int seconds, matching the existing
    hash-chain `compute_hash` convention)."""
    ts_int = int(row["timestamp"])
    flagged = 1 if (row["flagged"] or False) else 0
    details = row["details"] or "{}"
    # Same canonical form as Watch.compute_hash.
    payload = (
        f"{row['entry_id']}|{row['session_id']}|{row['agent_id']}|"
        f"{row['action']}|{row['tool']}|{details}|"
        f"{float(row['cost_usd']):.2f}|{ts_int}|{flagged}|"
        f"{row['prev_hash'] or ''}"
    )
    return payload.encode()


def _load_leaves(db_path: str, tenant_id: str,
                  upto_size: int | None = None) -> list[tuple[str, bytes]]:
    """Ordered list of (entry_id, leaf_hash) for a tenant's log.
    Ordered by (timestamp ASC, entry_id ASC) to make the tree
    deterministic even if two entries share a second.

    `upto_size`: if provided, return only the first N leaves —
    lets consistency proofs reconstruct older tree heads from
    the live log."""
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        sql = (
            "SELECT entry_id, session_id, agent_id, action, tool, "
            "details, cost_usd, timestamp, flagged, prev_hash "
            "FROM audit_log WHERE tenant_id = ? "
            "ORDER BY timestamp ASC, entry_id ASC"
        )
        rows = conn.execute(sql, (tenant_id,)).fetchall()
    finally:
        conn.close()

    out: list[tuple[str, bytes]] = []
    for i, row in enumerate(rows):
        if upto_size is not None and i >= upto_size:
            break
        leaf = merkle.leaf_hash(entry_leaf_bytes(row))
        out.append((row["entry_id"], leaf))
    return out


# ── Signed Tree Head ──────────────────────────────────────────────

def _sign(tree_size: int, root: bytes) -> dict[str, Any]:
    """Pick the signing algorithm based on env. Ed25519 beats HMAC
    when an Ed25519 seed/key is configured; otherwise stay on HMAC
    for back-compat with existing verifiers + clients.

    Triggered by any of:
      HALDIR_TREE_SIGNING_KEY_ED25519          (base64 32-byte raw)
      HALDIR_TREE_SIGNING_KEY_ED25519_SEED     (any string)
      HALDIR_STH_ALGORITHM=ed25519             (explicit opt-in)
    """
    import os
    want_ed25519 = bool(
        os.environ.get("HALDIR_TREE_SIGNING_KEY_ED25519")
        or os.environ.get("HALDIR_TREE_SIGNING_KEY_ED25519_SEED")
        or os.environ.get("HALDIR_STH_ALGORITHM", "").lower() == "ed25519"
    )
    if want_ed25519:
        key, source = merkle.load_ed25519_signing_key_from_env()
        sth = merkle.sign_sth(tree_size, root, key)
    else:
        key, source = merkle.load_signing_key_from_env()
        sth = merkle.sign_sth(tree_size, root, key)
    sth["signing_key_source"] = source
    return sth


def get_tree_head(db_path: str, tenant_id: str) -> dict[str, Any]:
    """Compute the current Merkle root + STH for a tenant's log."""
    leaves = [lh for _, lh in _load_leaves(db_path, tenant_id)]
    root = merkle.mth(leaves)
    sth = _sign(len(leaves), root)
    sth["tenant_id"] = tenant_id
    return sth


# ── Inclusion proofs ──────────────────────────────────────────────

def get_inclusion_proof(
    db_path: str, tenant_id: str, entry_id: str,
) -> dict[str, Any] | None:
    """Build the inclusion proof for a specific audit entry in the
    current tenant's tree. Returns None if the entry isn't found
    in this tenant's log."""
    loaded = _load_leaves(db_path, tenant_id)
    if not loaded:
        return None

    index = None
    for i, (eid, _) in enumerate(loaded):
        if eid == entry_id:
            index = i
            break
    if index is None:
        return None

    leaves = [lh for _, lh in loaded]
    path = merkle.inclusion_path(leaves, index)
    root = merkle.mth(leaves)
    sth = _sign(len(leaves), root)
    sth["tenant_id"] = tenant_id

    return {
        "algorithm":  "RFC6962-SHA256",
        "entry_id":   entry_id,
        "leaf_index": index,
        "leaf_hash":  leaves[index].hex(),
        "tree_size":  len(leaves),
        "root_hash":  root.hex(),
        "audit_path": merkle.proof_to_hex(path),
        "sth":        sth,
    }


# ── Consistency proofs ────────────────────────────────────────────

def get_consistency_proof(
    db_path: str, tenant_id: str,
    first_size: int, second_size: int,
) -> dict[str, Any] | None:
    """Prove that the tree of size `first_size` is a prefix of the
    tree of size `second_size`. Both sizes must be valid positions
    in the current log (i.e., second_size <= current_size).

    Returns None on invalid inputs (first_size > second_size,
    second_size exceeds current log size, etc.)."""
    if first_size <= 0 or second_size <= 0 or first_size > second_size:
        return None
    full = _load_leaves(db_path, tenant_id)
    if second_size > len(full):
        return None

    leaves = [lh for _, lh in full[:second_size]]
    first_leaves = leaves[:first_size]
    first_root = merkle.mth(first_leaves)
    second_root = merkle.mth(leaves)

    if first_size == second_size:
        path_hex: list[str] = []
    else:
        path_hex = merkle.proof_to_hex(
            merkle.consistency_path(leaves, first_size),
        )

    return {
        "algorithm":        "RFC6962-SHA256",
        "first_size":       first_size,
        "second_size":      second_size,
        "first_root":       first_root.hex(),
        "second_root":      second_root.hex(),
        "consistency_path": path_hex,
    }
