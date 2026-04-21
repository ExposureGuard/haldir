"""
Tests for the x402 pay-per-request surface.

Scope:

  - Protocol compliance: 402 responses carry a valid base64 PAYMENT-
    REQUIRED header whose decoded JSON matches the v2 PaymentRequired
    schema exactly (x402Version=2, resource, accepts[] with scheme /
    network / amount / asset / payTo / maxTimeoutSeconds).
  - Unpaid requests return 402 + PAYMENT-REQUIRED (not 401 / 403).
  - Paid requests (in HALDIR_X402_TEST_MODE) return 200 + PAYMENT-
    RESPONSE carrying a SettlementResponse.
  - Malformed PAYMENT-SIGNATURE → 400, not 500.
  - Disabled mode (HALDIR_X402_ENABLED != "1") returns 503 so agents
    can distinguish "not available" from "requires payment."
  - Manifest + /.well-known/x402.json list every paid endpoint with
    price + asset + network.
  - A successful payment writes an entry into the audit_log, so x402
    revenue becomes part of Haldir's own Merkle tree.

Run: python -m pytest tests/test_x402.py -v
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_x402  # noqa: E402


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _x402_env(monkeypatch):
    """Enable x402 + test mode + pin payTo for every test in this
    module so each assertion doesn't have to carry the ritual."""
    monkeypatch.setenv("HALDIR_X402_ENABLED",   "1")
    monkeypatch.setenv("HALDIR_X402_TEST_MODE", "1")
    monkeypatch.setenv(
        "HALDIR_X402_PAY_TO",
        "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    )
    monkeypatch.setenv("HALDIR_X402_NETWORK", "eip155:84532")


def _valid_payload(resource_url: str, amount_atomic: int) -> str:
    """Build a structurally-valid x402-v2 PaymentPayload, base64-encode
    it the way a real client would, and return the header value."""
    payload = {
        "x402Version": 2,
        "resource": {"url": resource_url},
        "accepted": {
            "scheme":            "exact",
            "network":           "eip155:84532",
            "amount":            str(amount_atomic),
            "asset":             haldir_x402.USDC_BASE_SEPOLIA,
            "payTo":             "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds": 60,
            "extra": {"name": "USDC", "version": "2"},
        },
        "payload": {
            "signature": "0x" + "ab" * 65,
            "authorization": {
                "from":        "0x857b06519E91e3A54538791bDbb0E22373e36b66",
                "to":          "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                "value":       str(amount_atomic),
                "validAfter":  "1700000000",
                "validBefore": "1900000000",
                "nonce":       "0x" + "f1" * 32,
            },
        },
        "extensions": {},
    }
    return base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode(),
    ).decode("ascii")


def _decode(b64: str) -> dict:
    """Reverse of _valid_payload for inspecting server-side headers."""
    padded = b64 + "=" * ((-len(b64)) % 4)
    return json.loads(base64.b64decode(padded))


# ── Protocol compliance on the 402 response ─────────────────────────

def test_unpaid_request_returns_402(haldir_client) -> None:
    r = haldir_client.get("/v1/x402/tree-head")
    assert r.status_code == 402


def test_402_carries_base64_payment_required_header(haldir_client) -> None:
    r = haldir_client.get("/v1/x402/tree-head")
    hdr = r.headers.get("PAYMENT-REQUIRED", "")
    assert hdr, "PAYMENT-REQUIRED header must be present on 402"
    decoded = _decode(hdr)
    # Every required v2 PaymentRequired field.
    assert decoded["x402Version"] == 2
    assert decoded["resource"]["url"].endswith("/v1/x402/tree-head")
    assert isinstance(decoded["accepts"], list) and decoded["accepts"]
    req = decoded["accepts"][0]
    for k in ("scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds"):
        assert k in req, f"PaymentRequirements missing field {k}"
    assert req["scheme"] == "exact"
    assert req["network"] == "eip155:84532"
    assert req["asset"] == haldir_x402.USDC_BASE_SEPOLIA


def test_pricing_matches_manifest(haldir_client) -> None:
    """Whatever the manifest advertises is what the 402 demands."""
    mf = haldir_client.get("/v1/x402/manifest").get_json()
    tree_head_res = next(
        r for r in mf["resources"] if r["resource"] == "tree-head"
    )
    r = haldir_client.get("/v1/x402/tree-head")
    hdr = _decode(r.headers["PAYMENT-REQUIRED"])
    assert hdr["accepts"][0]["amount"] == tree_head_res["price_usdc_atomic"]


# ── Paid path ────────────────────────────────────────────────────────

def test_valid_payment_returns_200_with_settlement(haldir_client) -> None:
    # Seed the demo tenant so tree-head has leaves.
    import haldir_demo_tamper
    haldir_demo_tamper.ensure_seeded()

    b64 = _valid_payload("http://localhost/v1/x402/tree-head", 1000)
    r = haldir_client.get(
        "/v1/x402/tree-head",
        headers={"PAYMENT-SIGNATURE": b64},
    )
    assert r.status_code == 200
    settle_hdr = r.headers.get("PAYMENT-RESPONSE", "")
    assert settle_hdr, "PAYMENT-RESPONSE header required on paid success"
    settlement = _decode(settle_hdr)
    assert settlement["success"] is True
    assert settlement["transaction"].startswith("0x")
    # Underlying resource body came through.
    body = r.get_json()
    assert "tree_size" in body and "root_hash" in body


def test_valid_payment_on_evidence_pack(haldir_client) -> None:
    import haldir_demo_tamper
    haldir_demo_tamper.ensure_seeded()
    b64 = _valid_payload("http://localhost/v1/x402/evidence-pack", 100000)
    r = haldir_client.get(
        "/v1/x402/evidence-pack",
        headers={"PAYMENT-SIGNATURE": b64},
    )
    assert r.status_code == 200
    body = r.get_json()
    # Evidence pack shape.
    for k in ("controls", "signatures", "tamper_evidence"):
        assert k in body


# ── Error cases ──────────────────────────────────────────────────────

def test_malformed_payment_signature_returns_400(haldir_client) -> None:
    r = haldir_client.get(
        "/v1/x402/tree-head",
        headers={"PAYMENT-SIGNATURE": "this-is-not-base64-json!!!"},
    )
    assert r.status_code == 400


def test_wrong_shape_payment_signature_returns_400(haldir_client) -> None:
    # Valid base64, valid JSON, wrong x402Version.
    bad = base64.b64encode(
        json.dumps({"x402Version": 1, "foo": "bar"}).encode(),
    ).decode()
    r = haldir_client.get(
        "/v1/x402/tree-head",
        headers={"PAYMENT-SIGNATURE": bad},
    )
    assert r.status_code == 400


def test_x402_disabled_returns_503(haldir_client, monkeypatch) -> None:
    """Agents need a distinct signal for 'surface exists but off' vs
    'payment required.' 503 beats a silent 404."""
    monkeypatch.setenv("HALDIR_X402_ENABLED", "0")
    r = haldir_client.get("/v1/x402/tree-head")
    assert r.status_code == 503
    assert "x402_not_enabled" in r.data.decode()


# ── Manifest + well-known ────────────────────────────────────────────

def test_manifest_lists_every_paid_endpoint(haldir_client) -> None:
    r = haldir_client.get("/v1/x402/manifest")
    assert r.status_code == 200
    mf = r.get_json()
    assert mf["x402Version"] == 2
    assert mf["service"] == "haldir"
    paths = {res["path"] for res in mf["resources"]}
    assert "/v1/x402/tree-head" in paths
    assert "/v1/x402/evidence-pack" in paths
    assert any("inclusion-proof" in p for p in paths)


def test_manifest_prices_include_human_and_atomic(haldir_client) -> None:
    mf = haldir_client.get("/v1/x402/manifest").get_json()
    for res in mf["resources"]:
        assert res["price_usdc_atomic"].isdigit()
        assert res["price_usdc"].startswith("$")
        assert res["asset"].startswith("0x")
        assert res["network"].startswith("eip155:")


def test_well_known_x402_mirrors_manifest(haldir_client) -> None:
    """Agentic-market and x402.org crawlers look at /.well-known/x402.json
    by convention. Same content as /v1/x402/manifest so we can't drift."""
    wk = haldir_client.get("/.well-known/x402.json").get_json()
    mf = haldir_client.get("/v1/x402/manifest").get_json()
    assert wk["resources"] == mf["resources"]
    assert wk["service"] == mf["service"]


# ── Audit integration: x402 payments become Merkle leaves ───────────

def test_successful_payment_logs_to_audit(haldir_client) -> None:
    """A verified x402 payment must write an audit_log row so the
    Merkle tree covers it. Meta-claim: Haldir's tamper-evidence story
    attests to its own revenue."""
    import api
    from haldir_db import get_db
    import haldir_demo_tamper

    haldir_demo_tamper.ensure_seeded()

    # Count before.
    conn = get_db(api.DB_PATH)
    before = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE tool = 'x402'",
    ).fetchone()[0]
    conn.close()

    b64 = _valid_payload("http://localhost/v1/x402/tree-head", 1000)
    r = haldir_client.get(
        "/v1/x402/tree-head",
        headers={"PAYMENT-SIGNATURE": b64},
    )
    assert r.status_code == 200

    conn = get_db(api.DB_PATH)
    after = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE tool = 'x402'",
    ).fetchone()[0]
    conn.close()
    assert after == before + 1


# ── Schema conformance (base64 + field coverage) ────────────────────

def test_payment_required_schema_matches_coinbase_reference() -> None:
    """Hand-build a PaymentRequired via the module, round-trip through
    base64, and assert every field the spec calls 'Required' is present
    and the right type."""
    doc = haldir_x402.make_payment_required(
        resource_url="https://haldir.xyz/v1/x402/tree-head",
        amount_atomic=1000,
        description="STH for tenant",
    )
    encoded = haldir_x402._b64_json_encode(doc)
    decoded = haldir_x402._b64_json_decode(encoded)
    assert decoded["x402Version"] == 2
    assert "resource" in decoded and decoded["resource"]["url"]
    assert "accepts" in decoded and isinstance(decoded["accepts"], list)
    req = decoded["accepts"][0]
    for field in ("scheme", "network", "amount", "asset", "payTo",
                   "maxTimeoutSeconds"):
        assert field in req
    # amount is a string of a positive integer.
    assert req["amount"].isdigit()
    assert int(req["amount"]) > 0
    # extra block advertises USDC version 2 for EIP-3009.
    assert req["extra"]["name"] == "USDC"
    assert req["extra"]["version"] == "2"
