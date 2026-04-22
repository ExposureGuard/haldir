"""
External transparency mirror — anchors every Haldir STH to a log that
lives outside Haldir's trust boundary.

Why this module exists:

  haldir_sth_log.py gave us a SELF-published record of every STH we
  ever signed. Strong, but defeatable by a single compromised process
  with DB write access — the attacker rewrites audit_log AND sth_log
  in one transaction and the tamper vanishes.

  This module closes that residual. On every newly-signed STH, we
  additionally publish the signed bytes to one or more EXTERNAL
  append-only logs. The external log's operator doesn't share a DB
  (or anything else) with Haldir. Now "undetectable rewrite" requires
  compromising Haldir's DB + every mirror + every auditor's pinned
  receipt, in the same window, without anyone noticing. That's a
  multi-order-of-magnitude harder attack than compromising Haldir
  alone.

  Same pattern Certificate Transparency uses with monitors, Sigstore
  uses with Rekor, and every serious transparency system uses at
  scale. Named after the transparency-log monitor role in RFC 6962.

Backend contract:

  Each backend is a callable `(sth_dict) -> dict`. The dict it
  returns carries whatever the backend produced — Rekor UUID + log
  index, file offset, webhook response, whatever. We persist that
  opaque dict in sth_mirror_receipts.receipt_json and let auditors
  interpret it per backend.

  A backend MUST be idempotent with respect to (tenant_id, tree_size).
  A second call for the same STH can return a fresh receipt if the
  backend assigns fresh identifiers, but it must NOT crash or
  duplicate the semantic entry. Failure to publish is recoverable —
  we log the error and carry on; the next STH will be mirrored anyway.

Configured backends (via HALDIR_TRANSPARENCY_MIRROR env):

  none           — default; no-op. Feature is opt-in.
  file:/path     — append-only JSONL. Good for dev + an on-disk
                   operator log that a separate process archives.
  http:URL       — POST the STH JSON to a URL; record the response.
                   Simplest way to plug in any immutable backend a
                   customer already runs (S3 object-lock bucket, a
                   write-once HTTP archiver, etc.).
  rekor:URL      — POST as a Rekor-style attestation. URL defaults
                   to https://rekor.sigstore.dev/api/v1/log/entries.
                   See docs/TRANSPARENCY.md for the exact shape
                   Rekor expects.

All backends fail CLOSED-INTO-LOGGED: a failure inserts a row with
success=0 and error_message populated, so an operator dashboard can
surface "mirror degraded" states without disrupting the STH-signing
path.

Env:

  HALDIR_TRANSPARENCY_MIRROR   backend URL / spec (see above)
                                default: "none"
  HALDIR_TRANSPARENCY_TIMEOUT  seconds (default 10) for HTTP backends

Usage:

  import haldir_transparency_mirror as mirror
  receipt = mirror.publish(sth_dict, tenant_id="t")
  # receipt has: backend, success, receipt_id, log_index, receipt_json
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Callable

import httpx

logger = logging.getLogger("haldir.transparency")


# ── Backend dispatch ────────────────────────────────────────────────

def _config() -> str:
    return os.environ.get("HALDIR_TRANSPARENCY_MIRROR", "none").strip() or "none"


def _timeout() -> float:
    try:
        return float(os.environ.get("HALDIR_TRANSPARENCY_TIMEOUT", "10"))
    except ValueError:
        return 10.0


def _parse_backend() -> tuple[str, str]:
    """Split 'scheme:target' into (scheme, target). 'none' is a
    special-case with target="". Unknown schemes → ('unknown', spec)."""
    spec = _config()
    if spec == "none":
        return ("none", "")
    if ":" in spec:
        scheme, _, target = spec.partition(":")
        return (scheme.lower(), target)
    return ("unknown", spec)


def publish(sth: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    """Mirror a single STH to the configured external backend. Always
    returns a receipt-shaped dict (never raises). Callers log the
    receipt to sth_mirror_receipts so an auditor can cross-reference
    against the external log later.

    On error, the returned dict has success=False and a populated
    error_message. We NEVER propagate an exception here — mirror
    failures must not block the Haldir STH-signing path."""
    scheme, target = _parse_backend()

    try:
        if scheme == "none":
            return _receipt(
                backend="none",
                success=False,
                error="mirror disabled (HALDIR_TRANSPARENCY_MIRROR=none)",
            )
        if scheme == "file":
            return _backend_file(sth, tenant_id, target)
        if scheme == "http" or scheme == "https":
            # "http://host/path" or "https://host/path" are both valid
            # direct webhook backends. We re-assemble the URL since
            # _parse_backend split once at the first colon.
            url = f"{scheme}:{target}"
            return _backend_http(sth, tenant_id, url)
        if scheme == "rekor":
            url = target or "https://rekor.sigstore.dev/api/v1/log/entries"
            return _backend_rekor(sth, tenant_id, url)
        return _receipt(
            backend="unknown",
            success=False,
            error=f"unknown backend scheme {scheme!r} in HALDIR_TRANSPARENCY_MIRROR",
        )
    except Exception as e:
        logger.exception("mirror publish failed", extra={"tenant": tenant_id})
        return _receipt(
            backend=scheme,
            success=False,
            error=f"{type(e).__name__}: {e}",
        )


def _receipt(
    *,
    backend: str,
    success: bool,
    receipt_id: str = "",
    log_index: int = 0,
    receipt_json: dict | None = None,
    error: str = "",
) -> dict[str, Any]:
    """Canonical receipt shape. Callers log this to the mirror table
    and to the auditor-facing endpoint verbatim."""
    return {
        "backend":       backend,
        "success":       bool(success),
        "receipt_id":    receipt_id,
        "log_index":     int(log_index),
        "receipt_json":  receipt_json or {},
        "error_message": error,
        "mirrored_at":   time.time(),
    }


# ── Backend: file ───────────────────────────────────────────────────

def _backend_file(sth: dict, tenant_id: str, path: str) -> dict:
    """Append-only JSONL on disk. Good for dev + an on-disk operator
    log that a separate process archives or rotates to a WORM
    bucket. Uses O_APPEND for atomic-per-line writes on POSIX."""
    if not path:
        return _receipt(
            backend="file",
            success=False,
            error="HALDIR_TRANSPARENCY_MIRROR=file:<path> requires a path",
        )
    # Ensure parent directory exists. If the operator pointed at a
    # directory that doesn't exist, that's a configuration error; log
    # rather than silently create several layers of parents.
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        return _receipt(
            backend=f"file:{path}",
            success=False,
            error=f"parent directory {parent} does not exist",
        )

    record = {
        "tenant_id":   tenant_id,
        "mirrored_at": time.time(),
        "sth":         sth,
    }
    line = json.dumps(record, separators=(",", ":")) + "\n"
    # O_APPEND guarantees each write is atomic up to PIPE_BUF on POSIX,
    # which for JSONL single-line records (typically <2KB) means no
    # torn writes from concurrent Haldir workers.
    with open(path, "a", encoding="utf-8") as f:
        pre = f.tell()
        f.write(line)
    return _receipt(
        backend=f"file:{path}",
        success=True,
        receipt_id=hashlib.sha256(line.encode()).hexdigest(),
        log_index=pre,  # byte offset at write time
        receipt_json={"path": path, "offset": pre, "bytes": len(line)},
    )


# ── Backend: http ───────────────────────────────────────────────────

def _backend_http(sth: dict, tenant_id: str, url: str) -> dict:
    """Plain HTTP POST of the STH to a custom archiver. Generic; any
    endpoint that accepts JSON and returns some identifier the caller
    can use to look up the attestation later."""
    payload = {"tenant_id": tenant_id, "sth": sth,
                "mirrored_at": time.time()}
    try:
        with httpx.Client(timeout=_timeout()) as c:
            r = c.post(url, json=payload, headers={
                "Content-Type": "application/json",
                "User-Agent":   "haldir-transparency-mirror/1",
            })
    except httpx.HTTPError as e:
        return _receipt(
            backend=f"http:{url}",
            success=False,
            error=f"{type(e).__name__}: {e}",
        )
    if r.status_code >= 400:
        return _receipt(
            backend=f"http:{url}",
            success=False,
            error=f"http {r.status_code}: {r.text[:200]}",
        )
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text}
    return _receipt(
        backend=f"http:{url}",
        success=True,
        receipt_id=str(body.get("id", "") or body.get("uuid", "")),
        log_index=int(body.get("logIndex", 0) or body.get("log_index", 0) or 0),
        receipt_json=body,
    )


# ── Backend: rekor ──────────────────────────────────────────────────

def _backend_rekor(sth: dict, tenant_id: str, url: str) -> dict:
    """Push to a Sigstore Rekor-compatible log.

    Shape: we send a `hashedrekord` entry binding the STH's canonical
    form (sha256) to the Ed25519 signature + embedded public key. This
    is the same shape `cosign attest` uses for arbitrary attestations.

    Requires the STH to be Ed25519-signed — HMAC STHs can't be pushed
    to Rekor because Rekor verifies with a public key and there's no
    public counterpart to a shared HMAC secret.

    If the STH isn't Ed25519-signed, we return a structured error
    receipt rather than silently falling back to a different scheme
    (surprising fallbacks are the root cause of most transparency
    bugs)."""
    import base64

    algorithm = sth.get("algorithm", "")
    if "Ed25519" not in algorithm:
        return _receipt(
            backend="rekor",
            success=False,
            error=(
                "Rekor mirror requires Ed25519-signed STHs. Set "
                "HALDIR_TREE_SIGNING_KEY_ED25519_SEED (or the raw key "
                "var) to enable asymmetric STH signing; current "
                f"algorithm={algorithm!r}"
            ),
        )
    pub_hex = sth.get("public_key", "")
    sig_hex = sth.get("signature", "")
    if not pub_hex or not sig_hex:
        return _receipt(
            backend="rekor",
            success=False,
            error="STH missing public_key or signature fields — nothing to push",
        )

    # Reconstruct the canonical STH bytes the signature covers. Must
    # match haldir_merkle._canonical_sth exactly or Rekor will fail
    # verification downstream.
    canonical = (
        f"sth:{sth['tree_size']}:{sth['root_hash']}:{sth['signed_at']}"
    ).encode()
    content_digest = hashlib.sha256(canonical).hexdigest()

    # Rekor expects the public key in PEM SubjectPublicKeyInfo format,
    # base64-encoded as a string. Convert the raw 32-byte Ed25519
    # pubkey into PEM.
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        pub_raw = bytes.fromhex(pub_hex)
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_b64 = base64.b64encode(pub_pem).decode()
    except Exception as e:
        return _receipt(
            backend="rekor",
            success=False,
            error=f"failed to PEM-encode Ed25519 public key: {e}",
        )

    try:
        sig_raw = bytes.fromhex(sig_hex)
        sig_b64 = base64.b64encode(sig_raw).decode()
    except ValueError:
        return _receipt(
            backend="rekor",
            success=False,
            error="signature field is not valid hex",
        )

    entry = {
        "apiVersion": "0.0.1",
        "kind":       "hashedrekord",
        "spec": {
            "signature": {
                "content":   sig_b64,
                "publicKey": {"content": pub_b64},
            },
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value":     content_digest,
                },
            },
        },
    }

    try:
        with httpx.Client(timeout=_timeout()) as c:
            r = c.post(url, json=entry, headers={
                "Content-Type": "application/json",
                "Accept":       "application/json",
                "User-Agent":   "haldir-transparency-mirror/1 (rekor)",
            })
    except httpx.HTTPError as e:
        return _receipt(
            backend="rekor",
            success=False,
            error=f"{type(e).__name__}: {e}",
        )

    if r.status_code >= 400:
        return _receipt(
            backend="rekor",
            success=False,
            error=f"rekor rejected entry: http {r.status_code}: {r.text[:300]}",
        )

    # Rekor returns a map with one key (the UUID) → entry metadata.
    try:
        body = r.json()
    except ValueError:
        return _receipt(
            backend="rekor",
            success=False,
            error=f"rekor returned non-JSON body: {r.text[:200]}",
        )
    if not isinstance(body, dict) or not body:
        return _receipt(
            backend="rekor",
            success=False,
            error="rekor returned empty response",
        )

    uuid_str = next(iter(body.keys()))
    entry_meta = body[uuid_str] if isinstance(body[uuid_str], dict) else {}
    log_index = int(entry_meta.get("logIndex", 0) or 0)

    return _receipt(
        backend="rekor",
        success=True,
        receipt_id=uuid_str,
        log_index=log_index,
        receipt_json=body,
    )


# ── Persistence ────────────────────────────────────────────────────

def record_receipt(
    db_path: str,
    tenant_id: str,
    tree_size: int,
    receipt: dict[str, Any],
) -> None:
    """Persist a mirror receipt to the sth_mirror_receipts table.
    Best-effort — DB errors here never propagate, matching the
    non-blocking contract of the whole mirror pipeline."""
    try:
        from haldir_db import get_db
    except Exception:
        return
    conn = get_db(db_path)
    try:
        conn.execute(
            "INSERT INTO sth_mirror_receipts "
            "(tenant_id, tree_size, backend, receipt_id, log_index, "
            " mirrored_at, success, receipt_json, error_message) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant_id,
                int(tree_size),
                str(receipt.get("backend", "")),
                str(receipt.get("receipt_id", "")),
                int(receipt.get("log_index", 0)),
                float(receipt.get("mirrored_at", time.time())),
                1 if receipt.get("success") else 0,
                json.dumps(receipt.get("receipt_json", {}),
                            separators=(",", ":"))[:100_000],
                str(receipt.get("error_message", ""))[:1000],
            ),
        )
        conn.commit()
    except Exception:
        logger.exception("mirror receipt write failed")
    finally:
        conn.close()


def list_receipts(
    db_path: str,
    tenant_id: str,
    tree_size: int | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return all recorded mirror receipts for a tenant. Optional
    tree_size filter for "what happened to this specific STH?" queries
    — useful when an auditor is diagnosing a divergence."""
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        if tree_size is not None:
            rows = conn.execute(
                "SELECT tenant_id, tree_size, backend, receipt_id, log_index, "
                "mirrored_at, success, receipt_json, error_message "
                "FROM sth_mirror_receipts "
                "WHERE tenant_id = ? AND tree_size = ? "
                "ORDER BY mirrored_at DESC LIMIT ?",
                (tenant_id, int(tree_size), int(limit)),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT tenant_id, tree_size, backend, receipt_id, log_index, "
                "mirrored_at, success, receipt_json, error_message "
                "FROM sth_mirror_receipts "
                "WHERE tenant_id = ? "
                "ORDER BY mirrored_at DESC LIMIT ?",
                (tenant_id, int(limit)),
            ).fetchall()
    finally:
        conn.close()
    out = []
    for row in rows:
        try:
            receipt_json = json.loads(row["receipt_json"] or "{}")
        except (ValueError, TypeError):
            receipt_json = {}
        out.append({
            "tenant_id":     row["tenant_id"],
            "tree_size":     int(row["tree_size"]),
            "backend":       row["backend"],
            "receipt_id":    row["receipt_id"],
            "log_index":     int(row["log_index"]),
            "mirrored_at":   float(row["mirrored_at"]),
            "success":       bool(row["success"]),
            "receipt_json":  receipt_json,
            "error_message": row["error_message"],
        })
    return out


# ── Hook used by haldir_audit_tree.get_tree_head ────────────────────

def mirror_and_record(
    db_path: str,
    tenant_id: str,
    sth: dict[str, Any],
) -> dict[str, Any]:
    """One-shot: publish the STH to the configured backend and
    persist the receipt. Returns the receipt dict so the caller can
    surface it on the STH response if they want (most callers will
    just ignore it and rely on /v1/audit/sth-log/mirror/receipts
    for lookup later)."""
    receipt = publish(sth, tenant_id=tenant_id)
    record_receipt(
        db_path, tenant_id, int(sth.get("tree_size", 0)), receipt,
    )
    return receipt
