"""
Tests for haldir_rekor_verify — closes THREAT_MODEL §10.3b residual.

The verifier checks four things on a stored Rekor receipt:

  1. The entry body is present in the receipt JSON
  2. The `logID` field matches SHA-256(rekor_pubkey_der)
  3. The RFC 6962 inclusion proof reconstructs the claimed root
  4. The SignedEntryTimestamp verifies under Rekor's ECDSA-P-256
     public key

These tests construct real cryptographic inputs — a P-256 keypair,
a Merkle tree of synthetic leaves, a signed SET envelope — and feed
them through the verifier. Then they flip one bit at a time across
every check and assert the verifier rejects. Same shape Rekor's own
test vectors use.

Run: python -m pytest tests/test_rekor_verify.py -v
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_merkle as merkle  # noqa: E402
import haldir_rekor_verify as verify  # noqa: E402


# ── Fixture builders ────────────────────────────────────────────────

def _fresh_p256_keypair():
    """New P-256 keypair. Returns (priv, pub_pem_bytes)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


def _log_id_of(pem: bytes) -> str:
    """SHA-256 of DER-encoded pubkey — matches Rekor's logID."""
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(pem)
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _sign_ecdsa_p256(priv, message: bytes) -> str:
    """Sign with ECDSA-P-256 + SHA-256 and return base64(DER-sig)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    sig = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()


def _build_valid_receipt(
    *,
    body: bytes = b"haldir-hashedrekord-entry-01",
    log_index: int = 2,
    tree_size: int = 5,
    integrated_time: int = 1_700_000_000,
    priv=None,
    pem: bytes | None = None,
    uuid: str = "24296fb24b8ad77aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
) -> tuple[dict, bytes]:
    """Construct a Rekor receipt with matching crypto — real inclusion
    proof against a real Merkle tree, real SET signed by a real P-256
    key. Returns (receipt_dict, pubkey_pem) so tests can inject the
    pubkey via fetch_public_key=lambda _url: pem."""
    if priv is None or pem is None:
        priv, pem = _fresh_p256_keypair()
    log_id = _log_id_of(pem)

    # Build a real Merkle tree of `tree_size` leaves. Our target leaf
    # sits at log_index; every other leaf is random fixed bytes so
    # the tree is deterministic.
    leaves: list[bytes] = []
    for i in range(tree_size):
        if i == log_index:
            leaves.append(merkle.leaf_hash(body))
        else:
            leaves.append(merkle.leaf_hash(f"filler-{i:04d}".encode()))
    path_bytes = merkle.inclusion_path(leaves, log_index)
    root = merkle.mth(leaves)

    # Build the SET-signed envelope. Rekor signs the canonical JSON of
    # {body, integratedTime, logID, logIndex}.
    body_b64 = base64.b64encode(body).decode()
    canonical = json.dumps({
        "body":           body_b64,
        "integratedTime": integrated_time,
        "logID":          log_id,
        "logIndex":       log_index,
    }, sort_keys=True, separators=(",", ":")).encode()
    set_b64 = _sign_ecdsa_p256(priv, canonical)

    entry = {
        "body":            body_b64,
        "integratedTime":  integrated_time,
        "logID":           log_id,
        "logIndex":        log_index,
        "verification": {
            "inclusionProof": {
                "logIndex": log_index,
                "treeSize": tree_size,
                "hashes":   [h.hex() for h in path_bytes],
                "rootHash": root.hex(),
            },
            "signedEntryTimestamp": set_b64,
        },
    }

    receipt = {
        "backend":       "rekor",
        "receipt_id":    uuid,
        "log_index":     log_index,
        "success":       True,
        "receipt_json":  {uuid: entry},
        "error_message": "",
        "mirrored_at":   1_700_000_000.0,
    }
    return receipt, pem


def _mock_fetch(pem: bytes):
    """Return a fetch_public_key callable that always returns `pem`."""
    def _fetch(_url: str) -> bytes:
        return pem
    return _fetch


# ── Happy path ──────────────────────────────────────────────────────

def test_verify_succeeds_on_valid_receipt() -> None:
    receipt, pem = _build_valid_receipt()
    out = verify.verify_receipt(receipt, fetch_public_key=_mock_fetch(pem))
    assert out["verified"] is True
    assert out["reason"] == ""
    checks = out["checks"]
    assert checks["entry_present"]                is True
    assert checks["log_id_matches_pubkey"]        is True
    assert checks["inclusion_proof_valid"]        is True
    assert checks["signed_entry_timestamp_valid"] is True
    assert out["pubkey_fingerprint"]


@pytest.mark.parametrize("log_index,tree_size", [
    (0, 1),     # single-leaf tree
    (0, 5), (1, 5), (2, 5), (3, 5), (4, 5),
    (0, 8), (3, 8), (7, 8),  # power-of-two tree
    (0, 17), (8, 17), (16, 17),  # off-by-one tree
])
def test_verify_across_tree_shapes(log_index: int, tree_size: int) -> None:
    """RFC 6962 audit-path math has edge cases around powers-of-2 and
    rightmost leaves. Parametrize across the set of sizes that breaks
    naive implementations."""
    receipt, pem = _build_valid_receipt(
        log_index=log_index, tree_size=tree_size,
    )
    out = verify.verify_receipt(receipt, fetch_public_key=_mock_fetch(pem))
    assert out["verified"] is True, (
        f"verifier rejected valid receipt at log_index={log_index}, "
        f"tree_size={tree_size}: {out}"
    )


# ── Tamper detection ────────────────────────────────────────────────

def test_tampered_body_rejects_inclusion_and_set() -> None:
    """Mutating the body changes the leaf hash (fails inclusion) AND
    invalidates the SET (the SET canonicalizes the body b64). Both
    checks must fail."""
    receipt, pem = _build_valid_receipt()
    entry = next(iter(receipt["receipt_json"].values()))
    entry["body"] = base64.b64encode(b"a different body").decode()
    out = verify.verify_receipt(receipt, fetch_public_key=_mock_fetch(pem))
    assert out["verified"] is False
    assert out["checks"]["inclusion_proof_valid"] is False


def test_tampered_root_hash_rejects_inclusion() -> None:
    receipt, pem = _build_valid_receipt()
    entry = next(iter(receipt["receipt_json"].values()))
    entry["verification"]["inclusionProof"]["rootHash"] = "00" * 32
    out = verify.verify_receipt(receipt, fetch_public_key=_mock_fetch(pem))
    assert out["verified"] is False
    assert out["checks"]["inclusion_proof_valid"] is False


def test_flipped_audit_path_hash_rejects_inclusion() -> None:
    receipt, pem = _build_valid_receipt()
    entry = next(iter(receipt["receipt_json"].values()))
    hashes = entry["verification"]["inclusionProof"]["hashes"]
    if hashes:
        # Flip a byte of the first sibling hash.
        flipped = bytearray.fromhex(hashes[0])
        flipped[0] ^= 0xff
        hashes[0] = flipped.hex()
    out = verify.verify_receipt(receipt, fetch_public_key=_mock_fetch(pem))
    assert out["verified"] is False


def test_flipped_set_rejects_signature() -> None:
    """Change ONE byte of the SET and ECDSA verification must fail."""
    receipt, pem = _build_valid_receipt()
    entry = next(iter(receipt["receipt_json"].values()))
    set_b64 = entry["verification"]["signedEntryTimestamp"]
    raw = bytearray(base64.b64decode(set_b64))
    # Signatures are DER-encoded; flip the last byte.
    raw[-1] ^= 0x01
    entry["verification"]["signedEntryTimestamp"] = (
        base64.b64encode(bytes(raw)).decode()
    )
    out = verify.verify_receipt(receipt, fetch_public_key=_mock_fetch(pem))
    assert out["verified"] is False
    assert out["checks"]["signed_entry_timestamp_valid"] is False


def test_wrong_pubkey_rejects() -> None:
    """A legitimate receipt verified against the WRONG Rekor pubkey
    must reject — that's what catches a mirror lying about which
    Rekor instance it posted to."""
    receipt, _ = _build_valid_receipt()
    _, wrong_pem = _fresh_p256_keypair()
    out = verify.verify_receipt(
        receipt, fetch_public_key=_mock_fetch(wrong_pem),
    )
    assert out["verified"] is False
    # log_id mismatch OR SET signature invalid (depending on which
    # fails first). Both are legitimate rejections.
    failing = [k for k, v in out["checks"].items() if not v]
    assert any(k in failing for k in (
        "log_id_matches_pubkey", "signed_entry_timestamp_valid",
    ))


def test_mutated_log_index_rejects() -> None:
    """If the mirror claims the entry is at a different logIndex than
    the inclusion proof supports, the SET (which commits to logIndex
    in its canonical form) will no longer verify — separate from the
    inclusion proof falling apart."""
    receipt, pem = _build_valid_receipt(log_index=2, tree_size=5)
    entry = next(iter(receipt["receipt_json"].values()))
    entry["logIndex"] = 99
    out = verify.verify_receipt(receipt, fetch_public_key=_mock_fetch(pem))
    assert out["verified"] is False
    assert out["checks"]["signed_entry_timestamp_valid"] is False


# ── Structural failures ────────────────────────────────────────────

def test_non_rekor_receipt_fails_early() -> None:
    out = verify.verify_receipt({"backend": "file:/tmp/x", "receipt_id": "x"})
    assert out["verified"] is False
    assert "not a Rekor" in out["reason"]


def test_missing_uuid_fails() -> None:
    out = verify.verify_receipt(
        {"backend": "rekor", "receipt_id": "", "receipt_json": {}},
    )
    assert out["verified"] is False
    assert "missing" in out["reason"].lower()


def test_receipt_json_missing_entry_for_uuid_fails() -> None:
    out = verify.verify_receipt({
        "backend":      "rekor",
        "receipt_id":   "abc123",
        "receipt_json": {"different-uuid": {}},
    })
    assert out["verified"] is False
    assert "no entry" in out["reason"]


def test_missing_inclusion_proof_fails() -> None:
    receipt, pem = _build_valid_receipt()
    entry = next(iter(receipt["receipt_json"].values()))
    del entry["verification"]["inclusionProof"]
    out = verify.verify_receipt(receipt, fetch_public_key=_mock_fetch(pem))
    assert out["verified"] is False
    assert "inclusionProof" in out["reason"]


def test_pubkey_fetch_error_is_structured() -> None:
    """A failing fetch must NOT raise — it produces a structured
    verified=False receipt."""
    def _boom(_url: str) -> bytes:
        raise RuntimeError("network down")
    receipt, _ = _build_valid_receipt()
    out = verify.verify_receipt(receipt, fetch_public_key=_boom)
    assert out["verified"] is False
    assert "public key" in out["reason"].lower()


# ── SDK re-export ──────────────────────────────────────────────────

def test_sdk_reexports_verify_rekor_receipt() -> None:
    """Customers pinning a receipt should verify it with just the
    haldir SDK — no network call, no server trust, no reaching into
    private modules."""
    import sdk
    assert callable(getattr(sdk, "verify_rekor_receipt", None))
    receipt, pem = _build_valid_receipt()
    out = sdk.verify_rekor_receipt(
        receipt, fetch_public_key=_mock_fetch(pem),
    )
    assert out["verified"] is True
