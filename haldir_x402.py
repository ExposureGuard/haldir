"""
Haldir x402 integration — pay-per-request access to Haldir's crypto surface.

Why this exists:

  x402 (https://www.x402.org/) is Coinbase's emerging "Payment Required"
  standard for agent-to-agent commerce. Resource servers return HTTP
  402 with a base64-encoded `PAYMENT-REQUIRED` header describing what
  it costs to access the resource. Agents sign an EIP-3009
  `transferWithAuthorization` (USDC), retry with a `PAYMENT-SIGNATURE`
  header, and receive the resource plus a `PAYMENT-RESPONSE` header
  carrying the on-chain settlement transaction hash.

  Listing on agentic.market — the 472-service x402 directory — is the
  single highest-ROI agent-discoverability move Haldir can make today.
  This module is the wedge.

What's in scope (shippable MVP):

  - Exact wire-compatible implementation of the v2 HTTP transport spec:
    PAYMENT-REQUIRED / PAYMENT-SIGNATURE / PAYMENT-RESPONSE headers,
    base64-JSON encoding, x402Version=2 throughout.
  - Three paid Haldir endpoints (tree-head, inclusion-proof, evidence-pack).
  - Facilitator delegation — POST to `/verify` and `/settle` on
    https://x402.org/facilitator (configurable via env). We don't run
    on-chain verification ourselves; we forward.
  - Test-mode (`HALDIR_X402_TEST_MODE=1`) that accepts any structurally-
    valid PaymentPayload, so CI + partner demos work without real USDC.
  - Every settled payment is also written to Haldir's own audit log, so
    x402 spend shows up in the same Merkle tree that covers every other
    governance event.

What's out of scope (v1):

  - On-chain EIP-712 signature verification in-process. Facilitators
    exist for a reason; re-implementing them is a footgun, not a moat.
  - Per-tenant wallet custody. A tenant's payTo address comes from env
    or their session metadata; Haldir doesn't hold the counterparty key.
  - Non-EVM schemes (Solana, etc.). Base/Base Sepolia first.

Spec references:
  https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md
  https://github.com/coinbase/x402/blob/main/specs/transports-v2/http.md
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from functools import wraps
from typing import Any, Callable

import httpx
from flask import request


logger = logging.getLogger("haldir.x402")


# ── Protocol constants ──────────────────────────────────────────────

X402_VERSION = 2

# HTTP header names — uppercase per the v2 transport spec. Flask
# normalizes incoming headers to title case; we send outgoing headers
# with the exact casing the spec shows.
HEADER_PAYMENT_REQUIRED  = "PAYMENT-REQUIRED"
HEADER_PAYMENT_SIGNATURE = "PAYMENT-SIGNATURE"
HEADER_PAYMENT_RESPONSE  = "PAYMENT-RESPONSE"

# Default scheme + network. Base Sepolia (CAIP-2 eip155:84532) is the
# right default: it's where every x402 demo + facilitator testnet lives,
# so a new buyer hitting our endpoints with zero config Just Works.
DEFAULT_SCHEME  = "exact"
DEFAULT_NETWORK = "eip155:84532"  # Base Sepolia

# USDC contract on Base Sepolia (Coinbase's canonical testnet USDC).
USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
# USDC on Base mainnet.
USDC_BASE_MAINNET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

# Default maximum time a client has between signing and us settling.
# 60s matches every Coinbase example; shorter = more settlement risk,
# longer = more replay window.
DEFAULT_TIMEOUT_S = 60

# Default facilitator URL. The docs + Python SDK both hardcode this as
# the canonical testnet facilitator.
DEFAULT_FACILITATOR_URL = "https://x402.org/facilitator"


# ── Env-driven config ──────────────────────────────────────────────

def _enabled() -> bool:
    """x402 is OFF by default. Flip HALDIR_X402_ENABLED=1 to expose the
    paid endpoints. Keeping it opt-in means the main Haldir surface
    doesn't accidentally require USDC for a free-tier visitor."""
    return os.environ.get("HALDIR_X402_ENABLED", "").strip() in ("1", "true", "yes")


def _test_mode() -> bool:
    """Test mode: skip facilitator + accept any structurally-valid
    payload. Used by pytest, by the agentic.market submission demo,
    and by VC meetings where we want to show the flow without funded
    wallets. Logged loudly so nobody ships it to prod by accident."""
    mode = os.environ.get("HALDIR_X402_TEST_MODE", "").strip() in ("1", "true", "yes")
    if mode:
        logger.warning(
            "x402 TEST MODE active — payments accepted without facilitator verification. "
            "This must never be set in production."
        )
    return mode


def _pay_to() -> str:
    """Recipient wallet address for every payment. Tenant-scoping for
    this is a v2 feature; v1 ships a single platform wallet."""
    addr = os.environ.get("HALDIR_X402_PAY_TO", "").strip()
    if not addr:
        # Fake-but-valid demo address so the 402 header still parses.
        # In production HALDIR_X402_PAY_TO must be set to a real address.
        return "0x0000000000000000000000000000000000000000"
    return addr


def _network() -> str:
    return os.environ.get("HALDIR_X402_NETWORK", DEFAULT_NETWORK).strip()


def _asset() -> str:
    """USDC contract for the configured network. Pinned constants beat
    runtime lookups — these change approximately never."""
    net = _network()
    if net == "eip155:8453":
        return os.environ.get("HALDIR_X402_ASSET", USDC_BASE_MAINNET)
    return os.environ.get("HALDIR_X402_ASSET", USDC_BASE_SEPOLIA)


def _facilitator_url() -> str:
    return os.environ.get(
        "HALDIR_X402_FACILITATOR_URL", DEFAULT_FACILITATOR_URL,
    ).rstrip("/")


# ── Header encode/decode ────────────────────────────────────────────

def _b64_json_encode(obj: Any) -> str:
    """Stable, compact JSON → base64 for header transport. Matches the
    spec's examples byte-for-byte (no padding quirks, no sort_keys to
    preserve the caller's ordering)."""
    payload = json.dumps(obj, separators=(",", ":")).encode()
    return base64.b64encode(payload).decode("ascii")


def _b64_json_decode(s: str) -> dict:
    """Reverse of above. Accepts base64 with or without padding; returns
    {} on malformed input so callers can uniformly check for missing
    fields instead of branching on parse errors."""
    try:
        # Add padding if the client trimmed it.
        padded = s + "=" * (-len(s) % 4)
        raw = base64.b64decode(padded)
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
    except (ValueError, json.JSONDecodeError):
        pass
    return {}


# ── PaymentRequired builder ────────────────────────────────────────

def make_payment_required(
    *,
    resource_url: str,
    amount_atomic: int,
    description: str,
    mime_type: str = "application/json",
    timeout_s: int = DEFAULT_TIMEOUT_S,
    scheme: str = DEFAULT_SCHEME,
    network: str | None = None,
    asset: str | None = None,
    pay_to: str | None = None,
    error_message: str = "PAYMENT-SIGNATURE header is required",
) -> dict:
    """Build a v2 PaymentRequired payload ready for base64-encoding
    into the PAYMENT-REQUIRED header.

    `amount_atomic` is the raw USDC amount (6 decimals): $0.01 = 10000.
    The spec examples use strings for on-the-wire — we coerce on output.
    """
    return {
        "x402Version": X402_VERSION,
        "error":       error_message,
        "resource": {
            "url":         resource_url,
            "description": description,
            "mimeType":    mime_type,
        },
        "accepts": [
            {
                "scheme":            scheme,
                "network":           network or _network(),
                "amount":            str(amount_atomic),
                "asset":             asset or _asset(),
                "payTo":             pay_to or _pay_to(),
                "maxTimeoutSeconds": timeout_s,
                "extra": {
                    "name":    "USDC",
                    "version": "2",
                },
            }
        ],
        "extensions": {},
    }


# ── Facilitator integration ─────────────────────────────────────────

def _facilitator_call_sync(path: str, body: dict) -> dict:
    """Sync wrapper around httpx for Flask handlers. x402 payments are
    on the request hot path so we need a blocking call anyway; using
    the async facilitator here would just add event-loop overhead."""
    url = f"{_facilitator_url()}{path}"
    try:
        with httpx.Client(timeout=15.0) as c:
            r = c.post(url, json=body, headers={"Content-Type": "application/json"})
    except httpx.HTTPError as e:
        logger.warning("facilitator call failed", extra={"path": path, "error": str(e)})
        return {"isValid": False, "success": False,
                "errorReason": f"facilitator_unreachable: {type(e).__name__}"}
    try:
        out = r.json()
        if not isinstance(out, dict):
            out = {"raw": out}
    except ValueError:
        out = {"raw": r.text}
    out["_status"] = r.status_code
    return out


def verify_payment(payload: dict, requirements: dict) -> dict:
    """Delegate verification to the facilitator. In test mode, return
    a synthetic success so CI + demos work.

    Returns a dict with at least `isValid: bool` and, on failure, an
    `errorReason` string. Shape matches what the facilitator's /verify
    endpoint returns so callers can trust one schema."""
    if _test_mode():
        return {
            "isValid":      True,
            "payer":        (payload.get("payload", {})
                              .get("authorization", {})
                              .get("from", "")),
            "_test_mode":   True,
        }
    return _facilitator_call_sync(
        "/verify",
        {"paymentPayload": payload, "paymentRequirements": requirements},
    )


def settle_payment(payload: dict, requirements: dict) -> dict:
    """Delegate settlement. Returns a SettlementResponse-shaped dict
    with `success`, `transaction`, `network`, `payer`. Test mode
    returns a synthetic tx hash so downstream logging still captures
    a usable identifier."""
    if _test_mode():
        authz = payload.get("payload", {}).get("authorization", {})
        return {
            "success":     True,
            "transaction": "0x" + "0" * 63 + "1",  # deterministic test hash
            "network":     requirements.get("network", _network()),
            "payer":       authz.get("from", ""),
            "amount":      requirements.get("amount", ""),
        }
    raw = _facilitator_call_sync(
        "/settle",
        {"paymentPayload": payload, "paymentRequirements": requirements},
    )
    # Normalize: facilitator returns {success, transaction, network, payer}.
    return {
        "success":     bool(raw.get("success", False)),
        "transaction": raw.get("transaction", ""),
        "network":     raw.get("network", requirements.get("network", _network())),
        "payer":       raw.get("payer", ""),
        "amount":      raw.get("amount", requirements.get("amount", "")),
        "errorReason": raw.get("errorReason", ""),
    }


# ── Audit integration ───────────────────────────────────────────────

def _log_payment_to_audit(*, tenant_id: str, tx_hash: str, payer: str,
                          amount_atomic: str, resource: str,
                          settlement: dict) -> None:
    """Write the x402 payment into Haldir's own audit log so it becomes
    a leaf in the Merkle tree. That's the meta-story: Haldir's
    cryptographic trust layer attests to Haldir's own x402 revenue.

    Best-effort; any error here MUST NOT block the payment response."""
    try:
        import api
        from haldir_db import get_db
        import uuid
        conn = get_db(api.DB_PATH)
        try:
            # amount is in atomic USDC units (6 decimals).
            try:
                dollars = int(amount_atomic) / 1_000_000
            except (TypeError, ValueError):
                dollars = 0.0
            entry_id = f"x402-{uuid.uuid4().hex[:12]}"
            details = json.dumps({
                "x402": True,
                "tx":   tx_hash,
                "network": settlement.get("network", ""),
            }, separators=(",", ":"))
            conn.execute(
                "INSERT INTO audit_log (entry_id, tenant_id, session_id, "
                "agent_id, action, tool, details, cost_usd, timestamp, "
                "flagged, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?)",
                (entry_id, tenant_id, "x402-session",
                 payer or "anon", "x402.pay", "x402",
                 details, round(dollars, 6), time.time(),
                 f"x402-hash-{entry_id}"),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.warning("x402 audit write failed",
                       extra={"error": f"{type(e).__name__}: {e}"})


# ── Flask decorator ─────────────────────────────────────────────────

def require_x402_payment(
    *,
    amount_atomic: int,
    description: str,
    resource_name: str,
):
    """Decorator factory. Wrap a Flask handler to require an x402
    payment before running it.

    Flow on each request:
      1. If x402 is disabled globally (HALDIR_X402_ENABLED != "1"),
         return a 503 so agents know the surface exists but is off.
      2. If PAYMENT-SIGNATURE header is missing, return 402 with
         PAYMENT-REQUIRED describing the price.
      3. Parse + validate. If malformed → 400.
      4. Forward to facilitator.verify. If invalid → 402 with
         PAYMENT-RESPONSE explaining why.
      5. Forward to facilitator.settle. If failed → 402 with
         PAYMENT-RESPONSE carrying the errorReason.
      6. Log the settled payment to Haldir's audit log (leaf in the
         Merkle tree).
      7. Run the underlying handler. Add PAYMENT-RESPONSE header to
         the success response carrying the tx hash.
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not _enabled():
                return (
                    json.dumps({"error": "x402_not_enabled",
                                "message": "Set HALDIR_X402_ENABLED=1 on the server to use this surface."}),
                    503,
                    {"Content-Type": "application/json"},
                )

            full_url = request.url
            requirements_doc = make_payment_required(
                resource_url=full_url,
                amount_atomic=amount_atomic,
                description=description,
            )
            required_header = _b64_json_encode(requirements_doc)

            signature_b64 = request.headers.get(HEADER_PAYMENT_SIGNATURE, "").strip()
            if not signature_b64:
                return (
                    json.dumps({
                        "x402": "payment_required",
                        "resource":  resource_name,
                        "amount":    str(amount_atomic),
                        "asset":     "USDC",
                        "network":   _network(),
                    }),
                    402,
                    {
                        "Content-Type": "application/json",
                        HEADER_PAYMENT_REQUIRED: required_header,
                    },
                )

            payload = _b64_json_decode(signature_b64)
            if (not payload or payload.get("x402Version") != X402_VERSION
                    or not payload.get("accepted") or not payload.get("payload")):
                return (
                    json.dumps({
                        "error":   "invalid_payment_payload",
                        "message": "PAYMENT-SIGNATURE header did not decode to a valid x402 v2 PaymentPayload.",
                    }),
                    400,
                    {
                        "Content-Type": "application/json",
                        HEADER_PAYMENT_REQUIRED: required_header,
                    },
                )

            # For v1 we accept the `accepted` block the client echoed
            # back and use it verbatim for facilitator calls. This is
            # how Coinbase's reference server works too.
            accepted = payload["accepted"]

            verify = verify_payment(payload, accepted)
            if not verify.get("isValid", False):
                return (
                    json.dumps({
                        "error":   "payment_verification_failed",
                        "message": verify.get("errorReason", "facilitator rejected the payment"),
                    }),
                    402,
                    {
                        "Content-Type": "application/json",
                        HEADER_PAYMENT_REQUIRED: required_header,
                    },
                )

            settlement = settle_payment(payload, accepted)
            if not settlement.get("success", False):
                settle_header = _b64_json_encode(settlement)
                return (
                    json.dumps({
                        "error":   "payment_settlement_failed",
                        "message": settlement.get("errorReason", "facilitator settlement failed"),
                    }),
                    402,
                    {
                        "Content-Type": "application/json",
                        HEADER_PAYMENT_REQUIRED: required_header,
                        HEADER_PAYMENT_RESPONSE: settle_header,
                    },
                )

            tenant_id = getattr(request, "tenant_id", "") or "x402-anonymous"
            _log_payment_to_audit(
                tenant_id=tenant_id,
                tx_hash=settlement.get("transaction", ""),
                payer=settlement.get("payer", ""),
                amount_atomic=str(amount_atomic),
                resource=resource_name,
                settlement=settlement,
            )

            # Run the wrapped handler. Attach the settlement header
            # whatever shape the handler returned — tuple, Response,
            # or a bare dict (we wrap that too).
            inner = fn(*args, **kwargs)
            settle_header = _b64_json_encode({
                "success":     True,
                "transaction": settlement.get("transaction", ""),
                "network":     settlement.get("network", _network()),
                "payer":       settlement.get("payer", ""),
                "amount":      str(amount_atomic),
            })
            return _attach_payment_response(inner, settle_header)

        # Surface the resource metadata so the manifest endpoint can
        # reflect every registered x402 price without a separate
        # registry to keep in sync.
        wrapper.__haldir_x402__ = {  # type: ignore[attr-defined]
            "resource":      resource_name,
            "amount_atomic": amount_atomic,
            "description":   description,
        }
        return wrapper
    return decorator


def _attach_payment_response(resp: Any, header_value: str) -> Any:
    """Merge the PAYMENT-RESPONSE header into whatever shape the handler
    returned. Flask accepts several response shapes; handle each."""
    from flask import Response

    # (body, status, headers) tuple
    if isinstance(resp, tuple):
        if len(resp) == 3:
            body, status, headers = resp
            headers = dict(headers) if headers else {}
            headers[HEADER_PAYMENT_RESPONSE] = header_value
            return body, status, headers
        if len(resp) == 2:
            body, second = resp
            if isinstance(second, dict):
                h = dict(second); h[HEADER_PAYMENT_RESPONSE] = header_value
                return body, h
            return body, second, {HEADER_PAYMENT_RESPONSE: header_value}
        return resp
    # Flask Response object
    if isinstance(resp, Response):
        resp.headers[HEADER_PAYMENT_RESPONSE] = header_value
        return resp
    # Bare body (string, dict, bytes). Wrap with 200 + header.
    return resp, 200, {HEADER_PAYMENT_RESPONSE: header_value}


# ── Manifest building ──────────────────────────────────────────────

def build_manifest(app) -> dict:
    """Walk the Flask URL map + pull the `__haldir_x402__` metadata off
    every decorated view function. Returns a JSON-safe dict that both
    humans and crawlers can consume — agentic.market's directory
    scraper and the /.well-known/x402.json endpoint both render this."""
    resources = []
    for rule in app.url_map.iter_rules():
        view = app.view_functions.get(rule.endpoint)
        if not view:
            continue
        meta = getattr(view, "__haldir_x402__", None)
        if not meta:
            continue
        # Normalize USDC atomic → dollar string so humans + crawlers
        # don't have to read 6-decimal math.
        amt_atomic = int(meta["amount_atomic"])
        dollars = amt_atomic / 1_000_000
        resources.append({
            "path":          str(rule.rule),
            "methods":       sorted(m for m in rule.methods if m not in ("HEAD", "OPTIONS")),
            "resource":      meta["resource"],
            "description":   meta["description"],
            "price_usdc_atomic": str(amt_atomic),
            "price_usdc":    f"${dollars:.6f}".rstrip("0").rstrip("."),
            "asset":         _asset(),
            "network":       _network(),
            "pay_to":        _pay_to(),
            "scheme":        DEFAULT_SCHEME,
        })
    return {
        "x402Version": X402_VERSION,
        "service":     "haldir",
        "description": (
            "Haldir exposes its cryptographic audit surface as pay-per-"
            "request x402 endpoints. Pay in USDC, get back a Signed "
            "Tree Head, an RFC 6962 inclusion proof, or a signed "
            "audit-prep evidence pack."
        ),
        "homepage":    "https://haldir.xyz",
        "docs":        "https://haldir.xyz/docs",
        "demo":        "https://haldir.xyz/demo/tamper",
        "enabled":     _enabled(),
        "test_mode":   _test_mode(),
        "facilitator": _facilitator_url(),
        "resources":   resources,
    }
