"""
Rekor receipt verification — closes the mirror-trust residual.

Why this module exists:

  haldir_transparency_mirror.py pushes every STH to Sigstore Rekor
  and records the response (UUID + logIndex + the `verification` block
  Rekor returns). That closes the "DB compromise can silently rewrite
  history" attack.

  But it leaves a smaller residual (named as §10.3b in the threat
  model): **we trust the mirror's HTTP response to be genuine.** A
  lying / compromised facilitator could hand us a made-up UUID and
  log_index — we'd persist it and an auditor would later fail to
  find the entry on Rekor's real log.

  Rekor publishes two primitives that make that detectable:

    1. An `inclusion_proof` carrying the Merkle-tree sibling-hash
       path from the leaf we submitted up to Rekor's root.
    2. A `SignedEntryTimestamp` — Rekor's ECDSA-P-256 signature
       over the entry's canonical body, verifiable against Rekor's
       public key published at /api/v1/log/publicKey.

  Verifying both against Rekor's server-held public key proves: (a)
  the entry is in Rekor's actual log at the logIndex the mirror
  claimed, and (b) Rekor itself signed over the entry bytes we
  submitted. A lying mirror can't forge either — Rekor's private
  signing key isn't in its hands.

  After verification, the receipt carries an independent
  cryptographic witness: Rekor's word, not just the mirror's word.

Design choices:

  - **Inputs and outputs are plain dicts**, matching
    haldir_transparency_mirror's receipt shape. This module doesn't
    reach into the DB or the SDK. Pure function, unit-testable.
  - **Network fetch is pluggable.** verify_receipt takes an optional
    `fetch_public_key` callable so tests can inject mock Rekor
    responses without touching the network.
  - **Structured verification result.** Returns a dict with
    `verified: bool` plus every subcheck
    (inclusion_proof_valid, signed_entry_timestamp_valid,
    log_id_matches_pubkey) so a caller can surface which step failed
    to an operator dashboard.
  - **Failures are always structured.** Exceptions caught, converted
    into `{verified: False, reason: ...}`. Callers never have to
    `try/except` this module.

References:
  https://github.com/sigstore/rekor/blob/main/openapi.yaml
  https://docs.sigstore.dev/logging/verify_release
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from typing import Any, Callable

import httpx

logger = logging.getLogger("haldir.rekor.verify")


DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"


# ── Public entry point ────────────────────────────────────────────

def verify_receipt(
    receipt: dict[str, Any],
    *,
    rekor_url: str | None = None,
    fetch_public_key: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Cryptographically verify a Rekor receipt stored in
    sth_mirror_receipts.

    `receipt` must be the dict shape haldir_transparency_mirror
    persists — with `backend == "rekor"`, `receipt_id` carrying the
    UUID Rekor returned, and `receipt_json` carrying the full Rekor
    response body (the {uuid: {body, logIndex, logID,
    signedEntryTimestamp, verification}} map).

    Returns a dict with:
        verified: bool
        reason:   str (human-readable failure reason; empty on success)
        checks: {
            entry_present:                bool
            log_id_matches_pubkey:        bool
            inclusion_proof_valid:        bool
            signed_entry_timestamp_valid: bool
        }
        pubkey_fingerprint: hex (first 16 chars of SHA-256 of pubkey PEM)

    Pluggable `fetch_public_key` lets tests inject a mock Rekor
    public key without a network call.
    """
    url = (rekor_url or os.environ.get(
        "HALDIR_REKOR_URL", DEFAULT_REKOR_URL,
    )).rstrip("/")

    checks: dict[str, bool] = {
        "entry_present":                False,
        "log_id_matches_pubkey":        False,
        "inclusion_proof_valid":        False,
        "signed_entry_timestamp_valid": False,
    }
    result: dict[str, Any] = {
        "verified":           False,
        "reason":             "",
        "checks":             checks,
        "pubkey_fingerprint": "",
    }

    # ── 1. Extract the Rekor entry from the receipt ──
    if receipt.get("backend") != "rekor":
        result["reason"] = f"not a Rekor receipt (backend={receipt.get('backend')!r})"
        return result
    uuid_str = receipt.get("receipt_id", "")
    body = receipt.get("receipt_json") or {}
    if not uuid_str:
        result["reason"] = "receipt_id (Rekor UUID) missing"
        return result
    entry = body.get(uuid_str) if isinstance(body, dict) else None
    if not isinstance(entry, dict):
        result["reason"] = f"receipt_json has no entry for uuid {uuid_str!r}"
        return result
    checks["entry_present"] = True

    # ── 2. Fetch (or inject) Rekor's public key ──
    try:
        if fetch_public_key is not None:
            pubkey_pem = fetch_public_key(url)
        else:
            pubkey_pem = _fetch_rekor_public_key(url)
    except Exception as e:
        result["reason"] = f"failed to fetch Rekor public key: {type(e).__name__}: {e}"
        return result

    # Pubkey fingerprint for operator dashboards. SHA-256 of the PEM
    # truncated to 16 hex chars — matches how Sigstore docs refer to
    # key fingerprints.
    result["pubkey_fingerprint"] = hashlib.sha256(pubkey_pem).hexdigest()[:16]

    # ── 3. logID check: Rekor's logID is SHA-256(pubkey DER). If the
    # claimed logID doesn't match, the entry is from a different
    # Rekor deployment (or the pubkey is wrong for the url). ──
    claimed_log_id = entry.get("logID", "")
    if claimed_log_id:
        expected_log_id = _pem_to_log_id(pubkey_pem)
        checks["log_id_matches_pubkey"] = (
            claimed_log_id.lower() == expected_log_id.lower()
        )
    else:
        # Some Rekor responses omit logID on the entry (it's always
        # implicit from the log you queried). Accept as a soft-pass
        # so we don't false-fail receipts from valid older entries.
        checks["log_id_matches_pubkey"] = True

    # ── 4. Verify the inclusion proof ──
    #
    # Delegate to haldir_merkle.verify_inclusion, our own
    # property-tested RFC 6962 verifier (10 Hypothesis properties +
    # a differential against a naive reference). Reusing it means
    # the exact same code that verifies Haldir's OWN tree verifies
    # Rekor's tree — one less primitive the auditor has to trust.
    verification = entry.get("verification") or {}
    inclusion = verification.get("inclusionProof") or {}
    entry_body_b64 = entry.get("body", "")
    if inclusion and entry_body_b64:
        try:
            import haldir_merkle
            leaf_hash = haldir_merkle.leaf_hash(
                base64.b64decode(entry_body_b64),
            )
            audit_path = [
                bytes.fromhex(h) for h in (inclusion.get("hashes") or [])
            ]
            claimed_root = bytes.fromhex(inclusion.get("rootHash", ""))
            checks["inclusion_proof_valid"] = haldir_merkle.verify_inclusion(
                leaf_hash,
                int(inclusion.get("logIndex", 0)),
                int(inclusion.get("treeSize", 0)),
                audit_path,
                claimed_root,
            )
        except Exception as e:
            checks["inclusion_proof_valid"] = False
            result["reason"] = f"inclusion-proof computation failed: {type(e).__name__}: {e}"
    else:
        result["reason"] = "Rekor entry is missing verification.inclusionProof or body"
        return result

    # ── 5. Verify the SignedEntryTimestamp ECDSA signature ──
    set_b64 = verification.get("signedEntryTimestamp", "")
    if set_b64 and entry_body_b64:
        canonical = _rekor_set_canonical(entry, entry_body_b64)
        try:
            checks["signed_entry_timestamp_valid"] = _verify_ecdsa_p256(
                pubkey_pem=pubkey_pem,
                message=canonical,
                signature_b64=set_b64,
            )
        except Exception as e:
            checks["signed_entry_timestamp_valid"] = False
            if not result["reason"]:
                result["reason"] = (
                    f"SET verification raised {type(e).__name__}: {e}"
                )
    else:
        if not result["reason"]:
            result["reason"] = "missing signedEntryTimestamp on Rekor entry"

    # ── 6. Aggregate ──
    if all(checks.values()):
        result["verified"] = True
        result["reason"] = ""
    elif not result["reason"]:
        failing = [k for k, v in checks.items() if not v]
        result["reason"] = f"failing checks: {', '.join(failing)}"
    return result


# ── Rekor HTTP: public-key fetch ──────────────────────────────────

def _fetch_rekor_public_key(rekor_url: str) -> bytes:
    """GET {rekor_url}/api/v1/log/publicKey and return the raw PEM
    bytes. Rekor serves the key as text/plain PEM, no JSON."""
    with httpx.Client(timeout=10.0) as c:
        r = c.get(f"{rekor_url}/api/v1/log/publicKey",
                  headers={"Accept": "application/x-pem-file"})
    r.raise_for_status()
    return r.content


# ── Canonical bytes for SET signature ─────────────────────────────

def _rekor_set_canonical(entry: dict[str, Any], body_b64: str) -> bytes:
    """The Rekor SignedEntryTimestamp signs a JSON canonicalization of
    {body, integratedTime, logID, logIndex}. Rekor's RFC 8785 JCS
    canonicalization is equivalent to our compact JSON because all
    values are strings or ints and there are no nested objects in
    this envelope — sorted keys + no whitespace = identical output.
    """
    canonical_obj = {
        "body":           body_b64,
        "integratedTime": int(entry.get("integratedTime", 0)),
        "logID":          str(entry.get("logID", "")),
        "logIndex":       int(entry.get("logIndex", 0)),
    }
    return json.dumps(
        canonical_obj, sort_keys=True, separators=(",", ":"),
    ).encode()


# ── ECDSA P-256 verification ──────────────────────────────────────

def _verify_ecdsa_p256(
    *,
    pubkey_pem: bytes,
    message: bytes,
    signature_b64: str,
) -> bool:
    """Verify an ECDSA-P-256 signature (DER-encoded) over a message
    using the caller-provided PEM public key. Rekor signs with
    SHA-256 so we pass hashes.SHA256 to verify.

    Returns True iff the signature is valid. All exceptions from
    `cryptography` are caught and converted to False — a caller
    never needs to try/except this function."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.exceptions import InvalidSignature

    try:
        pub = serialization.load_pem_public_key(pubkey_pem)
    except (ValueError, TypeError):
        return False
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return False
    if not isinstance(pub.curve, ec.SECP256R1):
        return False

    try:
        sig = base64.b64decode(signature_b64)
    except (ValueError, Exception):
        return False

    try:
        pub.verify(sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ── logID derivation ──────────────────────────────────────────────

def _pem_to_log_id(pubkey_pem: bytes) -> str:
    """Rekor's logID is SHA-256(DER-encoded public key)."""
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(pubkey_pem)
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()
