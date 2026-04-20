"""
Tests for asymmetric STH signing (Ed25519) + JWKS endpoint.

Why this matters: with HMAC-SHA256 the verifier needs the same secret
the signer uses — so anyone able to verify can also forge. Ed25519
splits signing (private key, Haldir) from verification (public key,
everyone else). A customer or auditor who pins the public key from
/.well-known/jwks.json at enrollment can reject any later STH Haldir
tries to forge, even if Haldir itself gets compromised.

Scope:
  1. sign_sth dispatches correctly on key type (bytes → HMAC,
     Ed25519PrivateKey → Ed25519).
  2. verify_sth round-trips both algorithms and rejects tamper /
     wrong-key cases.
  3. Ed25519 verification does NOT accept the same signature if the
     public key differs — asymmetric non-forgeability.
  4. load_ed25519_signing_key_from_env honors the documented
     precedence (raw → seed → HMAC seed reuse → ephemeral).
  5. /.well-known/jwks.json publishes a valid RFC 7517 OKP/Ed25519
     JWK whose `x` field is the raw public key base64url-encoded,
     and whose `kid` matches what an STH carries.
  6. get_tree_head auto-upgrades to Ed25519 when any of the trigger
     env vars are set; otherwise stays on HMAC for back-compat.

Run: python -m pytest tests/test_merkle_ed25519.py -v
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_merkle as merkle  # noqa: E402


# ── sign_sth / verify_sth (Ed25519 path) ────────────────────────────

def test_ed25519_sign_and_verify_round_trip() -> None:
    priv = merkle.derive_ed25519_key_from_seed("unit-test-seed-001")
    root = merkle.mth([merkle.leaf_hash(b"a"), merkle.leaf_hash(b"b")])
    sth = merkle.sign_sth(2, root, priv, signed_at=1_700_000_000)

    assert sth["algorithm"] == merkle.STH_ALGORITHM_ED25519
    assert sth["tree_size"] == 2
    assert sth["root_hash"] == root.hex()
    # The STH carries its own public key + stable kid.
    assert len(sth["public_key"]) == 64   # 32 bytes hex
    assert len(sth["key_id"]) == 16       # 16 hex chars (8 bytes)
    # Self-verifies against the embedded key.
    assert merkle.verify_sth(sth) is True
    # Also verifies when caller pins the public bytes explicitly.
    pub_bytes = priv.public_key().public_bytes_raw()
    assert merkle.verify_sth(sth, pub_bytes) is True


def test_ed25519_verification_rejects_different_public_key() -> None:
    """The whole point of asymmetric: a forged STH signed by a
    different private key must not verify against the original
    public key an auditor pinned."""
    real = merkle.derive_ed25519_key_from_seed("real-seed")
    attacker = merkle.derive_ed25519_key_from_seed("attacker-seed")
    root = merkle.mth([merkle.leaf_hash(b"x")])
    # Attacker signs a lie using their own key.
    forged = merkle.sign_sth(1, root, attacker, signed_at=1_700_000_000)
    # Auditor pinned `real`'s pubkey. Must reject.
    real_pub = real.public_key().public_bytes_raw()
    assert merkle.verify_sth(forged, real_pub) is False


def test_ed25519_rejects_tampered_tree_size() -> None:
    priv = merkle.derive_ed25519_key_from_seed("unit-test-seed-002")
    root = merkle.mth([merkle.leaf_hash(b"a")])
    sth = merkle.sign_sth(1, root, priv, signed_at=1_700_000_000)
    assert merkle.verify_sth(sth) is True
    # Mutate tree_size → signature no longer covers it.
    sth_bad = dict(sth, tree_size=99)
    assert merkle.verify_sth(sth_bad) is False


def test_hmac_path_still_works_for_back_compat() -> None:
    """An existing HMAC key must keep signing + verifying — customers
    who've pinned the HMAC key shouldn't need to migrate mid-stream."""
    key = merkle.derive_signing_key("legacy-seed")
    root = merkle.mth([merkle.leaf_hash(b"1"), merkle.leaf_hash(b"2")])
    sth = merkle.sign_sth(2, root, key, signed_at=1_700_000_000)
    assert sth["algorithm"] == merkle.STH_ALGORITHM
    assert merkle.verify_sth(sth, key) is True
    assert merkle.verify_sth(sth, merkle.derive_signing_key("wrong")) is False


def test_verify_sth_dispatches_on_algorithm_field() -> None:
    """A single verifier call must handle either algorithm without
    the caller knowing which was used in advance."""
    # Build one of each.
    hmac_key = merkle.derive_signing_key("x")
    ed_key = merkle.derive_ed25519_key_from_seed("y")
    root = merkle.mth([merkle.leaf_hash(b"z")])
    sth_h = merkle.sign_sth(1, root, hmac_key, signed_at=1)
    sth_e = merkle.sign_sth(1, root, ed_key, signed_at=1)
    # HMAC needs its key; Ed25519 self-verifies against embedded pubkey.
    assert merkle.verify_sth(sth_h, hmac_key) is True
    assert merkle.verify_sth(sth_e) is True


# ── load_ed25519_signing_key_from_env ────────────────────────────────

def test_env_precedence_raw_key_wins(monkeypatch) -> None:
    monkeypatch.setenv(
        "HALDIR_TREE_SIGNING_KEY_ED25519",
        base64.urlsafe_b64encode(b"\x01" * 32).decode().rstrip("="),
    )
    monkeypatch.setenv("HALDIR_TREE_SIGNING_KEY_ED25519_SEED", "ignored-seed")
    priv, source = merkle.load_ed25519_signing_key_from_env()
    assert source == "HALDIR_TREE_SIGNING_KEY_ED25519"
    # The raw-key bytes end up as the private key.
    assert priv.private_bytes_raw() == b"\x01" * 32


def test_env_precedence_seed_used_when_no_raw(monkeypatch) -> None:
    monkeypatch.delenv("HALDIR_TREE_SIGNING_KEY_ED25519", raising=False)
    monkeypatch.setenv("HALDIR_TREE_SIGNING_KEY_ED25519_SEED", "stable-seed-abc")
    priv, source = merkle.load_ed25519_signing_key_from_env()
    assert source == "HALDIR_TREE_SIGNING_KEY_ED25519_SEED"
    # Deterministic: same seed → same private key.
    priv2, _ = merkle.load_ed25519_signing_key_from_env()
    assert priv.private_bytes_raw() == priv2.private_bytes_raw()


def test_env_precedence_hmac_seed_reused_as_fallback(monkeypatch) -> None:
    monkeypatch.delenv("HALDIR_TREE_SIGNING_KEY_ED25519", raising=False)
    monkeypatch.delenv("HALDIR_TREE_SIGNING_KEY_ED25519_SEED", raising=False)
    monkeypatch.setenv("HALDIR_TREE_SIGNING_KEY", "hmac-side-seed")
    _, source = merkle.load_ed25519_signing_key_from_env()
    assert "reused seed" in source


# ── JWKS endpoint ────────────────────────────────────────────────────

def test_jwks_endpoint_publishes_valid_jwk(haldir_client, monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_TREE_SIGNING_KEY_ED25519_SEED", "jwks-test")
    r = haldir_client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    body = r.get_json()
    assert isinstance(body["keys"], list) and len(body["keys"]) == 1
    jwk = body["keys"][0]
    # Required JWK fields for OKP/Ed25519 (RFC 8037).
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["alg"] == "EdDSA"
    assert jwk["use"] == "sig"
    assert jwk["kid"]
    # x is base64url(pub_raw) without padding.
    x_raw = base64.urlsafe_b64decode(jwk["x"] + "==")
    assert len(x_raw) == 32


def test_jwks_kid_matches_sth_kid(haldir_client, monkeypatch) -> None:
    """An auditor pins `kid` from JWKS and expects it to appear on
    every STH signed by that key. Prevents confusion across rotations."""
    monkeypatch.setenv("HALDIR_TREE_SIGNING_KEY_ED25519_SEED", "kid-match-seed")
    # JWKS kid.
    jwk = haldir_client.get("/.well-known/jwks.json").get_json()["keys"][0]
    kid_from_jwks = jwk["kid"]
    # Now produce an STH via the same env-sourced key.
    priv, _ = merkle.load_ed25519_signing_key_from_env()
    root = merkle.mth([merkle.leaf_hash(b"dummy")])
    sth = merkle.sign_sth(1, root, priv, signed_at=1_700_000_000)
    assert sth["key_id"] == kid_from_jwks


# ── get_tree_head algorithm dispatch ─────────────────────────────────

def test_get_tree_head_stays_hmac_without_ed25519_env(monkeypatch) -> None:
    """Default path — no Ed25519 env, no algorithm override — keeps
    HMAC so existing clients / tests don't break on v0.4 upgrade."""
    import haldir_audit_tree
    for var in ("HALDIR_TREE_SIGNING_KEY_ED25519",
                "HALDIR_TREE_SIGNING_KEY_ED25519_SEED",
                "HALDIR_STH_ALGORITHM"):
        monkeypatch.delenv(var, raising=False)
    import api
    sth = haldir_audit_tree.get_tree_head(api.DB_PATH, "no-tenant")
    assert sth["algorithm"] == merkle.STH_ALGORITHM


def test_get_tree_head_flips_to_ed25519_when_seed_set(monkeypatch) -> None:
    import haldir_audit_tree
    monkeypatch.setenv("HALDIR_TREE_SIGNING_KEY_ED25519_SEED", "flip-seed")
    import api
    sth = haldir_audit_tree.get_tree_head(api.DB_PATH, "no-tenant")
    assert sth["algorithm"] == merkle.STH_ALGORITHM_ED25519
    assert sth["public_key"]
    assert sth["key_id"]


def test_get_tree_head_flips_via_explicit_algorithm_override(monkeypatch) -> None:
    """HALDIR_STH_ALGORITHM=ed25519 must also flip the switch even
    without the seed vars — lets operators try it with an ephemeral
    key before pinning a seed."""
    import haldir_audit_tree
    for var in ("HALDIR_TREE_SIGNING_KEY_ED25519",
                "HALDIR_TREE_SIGNING_KEY_ED25519_SEED"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HALDIR_STH_ALGORITHM", "ed25519")
    import api
    sth = haldir_audit_tree.get_tree_head(api.DB_PATH, "no-tenant")
    assert sth["algorithm"] == merkle.STH_ALGORITHM_ED25519


# ── Inclusion proof carries the Ed25519 STH ─────────────────────────

def test_inclusion_proof_sth_is_ed25519_when_configured(
    tmp_path, monkeypatch,
) -> None:
    import haldir_migrate
    import haldir_audit_tree
    monkeypatch.setenv("HALDIR_TREE_SIGNING_KEY_ED25519_SEED", "inc-test")
    db = str(tmp_path / "inc.db")
    haldir_migrate.apply_pending(db)

    from haldir_db import get_db
    conn = get_db(db)
    conn.execute(
        "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, "
        "action, tool, details, cost_usd, timestamp, flagged, prev_hash, "
        "entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?)",
        ("ent-1", "t", "s", "a", "act", "tool", "{}", 0.0, 100.0, "h"),
    )
    conn.commit()
    conn.close()

    proof = haldir_audit_tree.get_inclusion_proof(db, "t", "ent-1")
    assert proof is not None
    assert proof["sth"]["algorithm"] == merkle.STH_ALGORITHM_ED25519
    assert proof["sth"]["public_key"]
    # Self-verifying STH signature on the embedded pubkey.
    assert merkle.verify_sth(proof["sth"]) is True


# ── SDK re-exports ──────────────────────────────────────────────────

def test_sdk_exports_algorithm_constants() -> None:
    import sdk
    assert sdk.STH_ALGORITHM_HMAC == merkle.STH_ALGORITHM
    assert sdk.STH_ALGORITHM_ED25519 == merkle.STH_ALGORITHM_ED25519


def test_sdk_verify_sth_handles_ed25519() -> None:
    """Customers pinning a public key out of band must be able to
    verify an Ed25519 STH with just the SDK — no server call."""
    import sdk
    priv = merkle.derive_ed25519_key_from_seed("sdk-export-test")
    root = merkle.mth([merkle.leaf_hash(b"x")])
    sth = merkle.sign_sth(1, root, priv, signed_at=1_700_000_000)
    pub = priv.public_key().public_bytes_raw()
    assert sdk.verify_sth(sth, pub) is True
    # Wrong pubkey rejects.
    other = merkle.derive_ed25519_key_from_seed("other")
    assert sdk.verify_sth(sth, other.public_key().public_bytes_raw()) is False
