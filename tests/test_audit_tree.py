"""
Tests for the RFC 6962 audit-tree surface: haldir_merkle + haldir_audit_tree
+ the three /v1/audit/tree-head | inclusion-proof | consistency-proof
endpoints + SDK re-exports.

Two tranches:

  1. Pure unit tests on haldir_merkle / haldir_audit_tree — no Flask,
     deterministic, fast. Cover tree sizes 1..17 (one past every
     power-of-2 boundary the splitting logic has to handle).

  2. End-to-end HTTP tests through the Flask test client: log several
     audit entries, hit the three endpoints, verify the proofs offline
     via the SDK re-exports. Proves the whole round-trip.

Run: python -m pytest tests/test_audit_tree.py -v
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_merkle as merkle  # noqa: E402


@pytest.fixture(autouse=True)
def _lift_agent_cap(monkeypatch):
    """The shared bootstrap tenant accumulates sessions across the
    suite — past the free-tier agent cap of 1. Lift it so tests
    that mint sessions don't hit the tier limiter.

    Matches the pattern used in test_compliance_score.py and
    test_admin.py."""
    import copy
    import api
    patched = copy.deepcopy(api.TIER_LIMITS)
    patched["free"]["agents"] = 999
    monkeypatch.setattr(api, "TIER_LIMITS", patched)


# ── Pure-function tests (no DB, no Flask) ────────────────────────────

def test_empty_tree_root_is_sha256_of_empty_string() -> None:
    """RFC 6962 §2.1: the MTH of an empty input is SHA-256("")."""
    import hashlib
    assert merkle.mth([]) == hashlib.sha256(b"").digest()


def test_single_leaf_root_equals_leaf_hash() -> None:
    leaf = merkle.leaf_hash(b"hello")
    assert merkle.mth([leaf]) == leaf


def test_inclusion_proof_round_trip_all_indices() -> None:
    """For tree sizes 1..17, every leaf's inclusion proof must verify
    back to the root."""
    for n in range(1, 18):
        leaves = [merkle.leaf_hash(f"entry-{i}".encode()) for i in range(n)]
        root = merkle.mth(leaves)
        for i in range(n):
            proof = merkle.generate_inclusion_proof(leaves, i)
            assert proof["root_hash"] == root.hex()
            assert merkle.verify_inclusion_hex(proof), (
                f"inclusion proof failed at n={n} i={i}"
            )


def test_inclusion_proof_tamper_flips_sibling() -> None:
    """Tampering with any sibling hash must fail verification."""
    leaves = [merkle.leaf_hash(f"e{i}".encode()) for i in range(8)]
    proof = merkle.generate_inclusion_proof(leaves, 3)
    assert merkle.verify_inclusion_hex(proof)
    # Corrupt the first sibling hash.
    proof["audit_path"][0] = "00" * 32
    assert not merkle.verify_inclusion_hex(proof)


def test_inclusion_proof_tamper_wrong_root_rejected() -> None:
    leaves = [merkle.leaf_hash(f"e{i}".encode()) for i in range(6)]
    proof = merkle.generate_inclusion_proof(leaves, 2)
    proof["root_hash"] = "ff" * 32
    assert not merkle.verify_inclusion_hex(proof)


def test_consistency_proof_round_trip_all_pairs() -> None:
    """For every (m, n) with 1 <= m <= n <= 17, the consistency proof
    must verify both first_root and second_root."""
    for n in range(1, 18):
        leaves = [merkle.leaf_hash(f"x{i}".encode()) for i in range(n)]
        second_root = merkle.mth(leaves)
        for m in range(1, n + 1):
            first_leaves = leaves[:m]
            first_root = merkle.mth(first_leaves)
            if m == n:
                path: list[str] = []
            else:
                path = merkle.proof_to_hex(merkle.consistency_path(leaves, m))
            proof = {
                "first_size":       m,
                "second_size":      n,
                "first_root":       first_root.hex(),
                "second_root":      second_root.hex(),
                "consistency_path": path,
            }
            assert merkle.verify_consistency_hex(proof), (
                f"consistency proof failed at m={m} n={n}"
            )


def test_consistency_proof_rejects_fork() -> None:
    """If the later tree diverges (not a strict extension), the proof
    from the real later tree must not verify against a mutated
    first_root."""
    leaves = [merkle.leaf_hash(f"z{i}".encode()) for i in range(10)]
    path = merkle.proof_to_hex(merkle.consistency_path(leaves, 6))
    proof = {
        "first_size":       6,
        "second_size":      10,
        "first_root":       ("cc" * 32),  # wrong first_root
        "second_root":      merkle.mth(leaves).hex(),
        "consistency_path": path,
    }
    assert not merkle.verify_consistency_hex(proof)


def test_sth_signature_round_trip() -> None:
    root = merkle.mth([merkle.leaf_hash(b"a"), merkle.leaf_hash(b"b")])
    key = merkle.derive_signing_key("test-seed")
    sth = merkle.sign_sth(2, root, key, signed_at=1_700_000_000)
    assert merkle.verify_sth(sth, key)
    # Different key → signature fails.
    assert not merkle.verify_sth(sth, merkle.derive_signing_key("other"))
    # Tamper the tree_size claim.
    sth_bad = dict(sth, tree_size=3)
    assert not merkle.verify_sth(sth_bad, key)


# ── haldir_audit_tree wrapper tests (DB-backed) ─────────────────────

def _isolated_db(tmp_path) -> str:
    """Fresh SQLite DB with the full schema applied. Returns path."""
    import haldir_migrate
    db = str(tmp_path / "audit_tree.db")
    haldir_migrate.apply_pending(db)
    return db


def _insert_audit_row(db: str, tenant: str, entry_id: str,
                        ts: float, action: str = "use") -> None:
    """Insert a raw audit_log row. We don't go through Watch because
    tests here exercise the Merkle layer, not the chain computation."""
    from haldir_db import get_db
    conn = get_db(db)
    conn.execute(
        "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, "
        "action, tool, details, cost_usd, timestamp, flagged, prev_hash, "
        "entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?)",
        (entry_id, tenant, "sess-x", "agent-x", action, "stripe",
         "{}", 0.50, ts, "deadbeef" + entry_id[:4]),
    )
    conn.commit()
    conn.close()


def test_tree_head_empty_tenant(tmp_path) -> None:
    import haldir_audit_tree
    db = _isolated_db(tmp_path)
    sth = haldir_audit_tree.get_tree_head(db, "no-entries")
    assert sth["tree_size"] == 0
    # Root must be SHA-256("") for the empty tree.
    import hashlib
    assert sth["root_hash"] == hashlib.sha256(b"").hexdigest()
    assert sth["algorithm"].startswith("HMAC")


def test_tree_head_populated_tenant(tmp_path) -> None:
    import haldir_audit_tree
    db = _isolated_db(tmp_path)
    for i in range(5):
        _insert_audit_row(db, "tnt-5", f"entry-{i:03d}", ts=1000.0 + i)
    sth = haldir_audit_tree.get_tree_head(db, "tnt-5")
    assert sth["tree_size"] == 5
    assert sth["tenant_id"] == "tnt-5"
    # Root must NOT be the empty-tree hash.
    import hashlib
    assert sth["root_hash"] != hashlib.sha256(b"").hexdigest()


def test_tree_is_tenant_scoped(tmp_path) -> None:
    import haldir_audit_tree
    db = _isolated_db(tmp_path)
    for i in range(3):
        _insert_audit_row(db, "tnt-a", f"a-{i}", ts=1000.0 + i)
    for i in range(7):
        _insert_audit_row(db, "tnt-b", f"b-{i}", ts=2000.0 + i)
    sth_a = haldir_audit_tree.get_tree_head(db, "tnt-a")
    sth_b = haldir_audit_tree.get_tree_head(db, "tnt-b")
    assert sth_a["tree_size"] == 3
    assert sth_b["tree_size"] == 7
    assert sth_a["root_hash"] != sth_b["root_hash"]


def test_inclusion_proof_for_real_entry(tmp_path) -> None:
    import haldir_audit_tree
    db = _isolated_db(tmp_path)
    entry_ids = [f"id-{i:03d}" for i in range(11)]
    for i, eid in enumerate(entry_ids):
        _insert_audit_row(db, "tnt-inc", eid, ts=1000.0 + i)
    proof = haldir_audit_tree.get_inclusion_proof(db, "tnt-inc", "id-004")
    assert proof is not None
    assert proof["algorithm"] == "RFC6962-SHA256"
    assert proof["entry_id"] == "id-004"
    assert proof["leaf_index"] == 4
    assert proof["tree_size"] == 11
    assert merkle.verify_inclusion_hex(proof)


def test_inclusion_proof_missing_entry(tmp_path) -> None:
    import haldir_audit_tree
    db = _isolated_db(tmp_path)
    _insert_audit_row(db, "tnt-miss", "real-entry", ts=1000.0)
    assert haldir_audit_tree.get_inclusion_proof(
        db, "tnt-miss", "does-not-exist",
    ) is None


def test_consistency_proof_between_snapshots(tmp_path) -> None:
    """Record 5 entries, compute tree_1 (size=3) vs tree_2 (size=5);
    their consistency proof must verify."""
    import haldir_audit_tree
    db = _isolated_db(tmp_path)
    for i in range(5):
        _insert_audit_row(db, "tnt-cn", f"c-{i}", ts=1000.0 + i)
    proof = haldir_audit_tree.get_consistency_proof(db, "tnt-cn", 3, 5)
    assert proof is not None
    assert merkle.verify_consistency_hex(proof)


def test_consistency_proof_same_size_is_trivial(tmp_path) -> None:
    import haldir_audit_tree
    db = _isolated_db(tmp_path)
    for i in range(4):
        _insert_audit_row(db, "tnt-same", f"s-{i}", ts=1000.0 + i)
    proof = haldir_audit_tree.get_consistency_proof(db, "tnt-same", 4, 4)
    assert proof is not None
    assert proof["first_root"] == proof["second_root"]
    assert proof["consistency_path"] == []


def test_consistency_proof_invalid_range(tmp_path) -> None:
    import haldir_audit_tree
    db = _isolated_db(tmp_path)
    for i in range(3):
        _insert_audit_row(db, "tnt-bad", f"x-{i}", ts=1000.0 + i)
    # first > second
    assert haldir_audit_tree.get_consistency_proof(db, "tnt-bad", 3, 2) is None
    # second > current log size
    assert haldir_audit_tree.get_consistency_proof(db, "tnt-bad", 1, 999) is None
    # zero / negative
    assert haldir_audit_tree.get_consistency_proof(db, "tnt-bad", 0, 2) is None


# ── HTTP endpoint tests ──────────────────────────────────────────────

def _log(client, key: str, session_id: str, action: str) -> dict:
    return client.post(
        "/v1/audit",
        json={"session_id": session_id, "tool": "stripe",
              "action": action, "cost_usd": 0.25},
        headers={"Authorization": f"Bearer {key}"},
    ).get_json()


def _mint_session(client, key: str) -> str:
    r = client.post(
        "/v1/sessions",
        json={"agent_id": "audit-tree-test", "scopes": ["read", "execute"]},
        headers={"Authorization": f"Bearer {key}"},
    )
    body = r.get_json()
    assert r.status_code == 201, f"session mint failed: {r.status_code} {body}"
    return body["session_id"]


def test_endpoint_tree_head(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(
        "/v1/audit/tree-head",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    body = r.get_json()
    for k in ("tree_size", "root_hash", "signature", "algorithm", "signed_at"):
        assert k in body


def test_endpoint_inclusion_proof_round_trip(haldir_client, bootstrap_key) -> None:
    sid = _mint_session(haldir_client, bootstrap_key)
    # Log a couple entries so we have something to prove inclusion of.
    logged = _log(haldir_client, bootstrap_key, sid, "charge-merkle-1")
    entry_id = logged.get("entry_id") or logged.get("id")
    assert entry_id, f"no entry_id in POST /v1/audit response: {logged}"
    _log(haldir_client, bootstrap_key, sid, "charge-merkle-2")

    r = haldir_client.get(
        f"/v1/audit/inclusion-proof/{entry_id}",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    proof = r.get_json()
    assert proof["entry_id"] == entry_id
    # SDK re-export must verify the proof offline.
    import haldir_merkle as m
    assert m.verify_inclusion_hex(proof)


def test_endpoint_inclusion_proof_missing_returns_404(
    haldir_client, bootstrap_key,
) -> None:
    r = haldir_client.get(
        "/v1/audit/inclusion-proof/not-a-real-entry-id-xyz",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 404


def test_endpoint_consistency_proof_round_trip(
    haldir_client, bootstrap_key,
) -> None:
    sid = _mint_session(haldir_client, bootstrap_key)
    # Ensure at least 2 entries exist.
    _log(haldir_client, bootstrap_key, sid, "consistency-1")
    _log(haldir_client, bootstrap_key, sid, "consistency-2")
    # Tree head to find current size.
    th = haldir_client.get(
        "/v1/audit/tree-head",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    ).get_json()
    size = int(th["tree_size"])
    if size < 2:
        pytest.skip("need >=2 audit entries for consistency proof")
    first = max(1, size - 1)
    r = haldir_client.get(
        f"/v1/audit/consistency-proof?first={first}&second={size}",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    proof = r.get_json()
    import haldir_merkle as m
    assert m.verify_consistency_hex(proof)


def test_endpoint_consistency_proof_invalid_range_returns_400(
    haldir_client, bootstrap_key,
) -> None:
    r = haldir_client.get(
        "/v1/audit/consistency-proof?first=99999&second=99998",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400


def test_endpoints_require_audit_read_scope(haldir_client, bootstrap_key) -> None:
    # Mint a key that has no audit:read scope.
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "no-audit-scope", "scopes": ["sessions:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    narrow = r.get_json()["key"]
    r2 = haldir_client.get(
        "/v1/audit/tree-head",
        headers={"Authorization": f"Bearer {narrow}"},
    )
    assert r2.status_code == 403
    assert r2.get_json()["required"] == "audit:read"


# ── SDK re-exports ───────────────────────────────────────────────────

def test_sdk_reexports_verify_functions() -> None:
    import sdk
    assert callable(getattr(sdk, "verify_inclusion_proof", None))
    assert callable(getattr(sdk, "verify_consistency_proof", None))
    assert callable(getattr(sdk, "verify_sth", None))


def test_sdk_verify_inclusion_proof_works_offline() -> None:
    """A customer archiving a single audit row + its proof can verify
    it without any network call — only the haldir SDK package."""
    import sdk
    leaves = [merkle.leaf_hash(f"sdk-{i}".encode()) for i in range(6)]
    proof = merkle.generate_inclusion_proof(leaves, 2)
    assert sdk.verify_inclusion_proof(proof)
    proof["root_hash"] = "00" * 32
    assert not sdk.verify_inclusion_proof(proof)


# ── Evidence pack embeds tamper_evidence section ────────────────────

def test_evidence_pack_embeds_tree_head(tmp_path) -> None:
    import haldir_compliance
    db = _isolated_db(tmp_path)
    for i in range(4):
        _insert_audit_row(db, "tnt-pack", f"p-{i}", ts=1000.0 + i)
    pack = haldir_compliance.build_evidence_pack(db, "tnt-pack")
    assert "tamper_evidence" in pack
    te = pack["tamper_evidence"]
    assert te["tree_size"] == 4
    assert te["algorithm"] == "RFC6962-SHA256"
    assert len(te["root_hash"]) == 64  # SHA-256 hex


def test_evidence_pack_markdown_mentions_merkle(tmp_path) -> None:
    import haldir_compliance
    db = _isolated_db(tmp_path)
    _insert_audit_row(db, "tnt-md", "md-1", ts=1000.0)
    pack = haldir_compliance.build_evidence_pack(db, "tnt-md")
    md = haldir_compliance.render_markdown(pack)
    assert "Signed Tree Head" in md
    assert "RFC6962" in md or "RFC 6962" in md


# ── Readiness score integrates the new criterion ────────────────────
# (Full integration is exercised in tests/test_compliance_score.py
# against the shared api.DB_PATH — here we just unit-test the new
# evaluator directly so we don't duplicate DB-init boilerplate.)

def test_tamper_evidence_criterion_warns_on_empty_log(tmp_path) -> None:
    import haldir_compliance_score as score
    db = _isolated_db(tmp_path)
    r = score._evaluate_tamper_evidence(db, "no-entries")
    assert r.key == "tamper_evidence"
    assert r.control == "CC7.2"
    assert r.state in ("warn", "pass")  # either "empty" warn or ephemeral warn


def test_tamper_evidence_criterion_passes_with_stable_key(tmp_path, monkeypatch) -> None:
    import haldir_compliance_score as score
    monkeypatch.setenv("HALDIR_TREE_SIGNING_KEY", "some-stable-key-material")
    db = _isolated_db(tmp_path)
    _insert_audit_row(db, "tnt-te", "te-1", ts=1000.0)
    r = score._evaluate_tamper_evidence(db, "tnt-te")
    assert r.state == "pass"
    assert "1-leaf" in r.reason or "1 leaf" in r.reason or "1 " in r.reason
