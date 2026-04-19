"""
Tests for /demo/tamper — the adversarial tamper-evidence demo.

Covers:

  - GET /demo/tamper renders the untampered page
  - POST /demo/tamper/mutate actually mutates the DB row
  - GET after mutate shows the tampered banner + red result
  - POST /demo/tamper/reset restores the original row
  - The rendered proof verifies cryptographically in the untampered
    state and fails cryptographically after tampering (not just a
    visual banner flip — the actual Merkle verifier disagrees).
  - The demo tenant is isolated — no leak into other tenants.

Run: python -m pytest tests/test_demo_tamper.py -v
"""

from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Page flow ────────────────────────────────────────────────────────

def test_page_renders_untampered_by_default(haldir_client) -> None:
    # Make sure we start clean even if a prior test left it mutated.
    haldir_client.post("/demo/tamper/reset")
    r = haldir_client.get("/demo/tamper")
    assert r.status_code == 200
    body = r.data.decode()
    # The applied banner (class="banner banner-ok") — not the CSS rule.
    assert 'class="banner banner-ok"' in body
    assert "Untampered" in body
    assert "demo-entry-003" in body
    assert "VERIFIES" in body
    # No tamper indicators in the clean state.
    assert 'class="banner banner-bad"' not in body
    assert "TAMPERED" not in body


def test_mutate_flips_the_banner(haldir_client) -> None:
    haldir_client.post("/demo/tamper/reset")
    # Tamper.
    r = haldir_client.post("/demo/tamper/mutate")
    assert r.status_code == 303
    assert r.headers["Location"].endswith("/demo/tamper")
    # Follow and confirm state.
    body = haldir_client.get("/demo/tamper").data.decode()
    assert 'class="banner banner-bad"' in body
    assert "Tamper detected" in body
    assert "TAMPERED" in body
    assert "FAILS" in body
    # Reset (leave things clean for other tests in session).
    haldir_client.post("/demo/tamper/reset")


def test_reset_restores_untampered_state(haldir_client) -> None:
    haldir_client.post("/demo/tamper/mutate")
    assert 'class="banner banner-bad"' in haldir_client.get("/demo/tamper").data.decode()
    r = haldir_client.post("/demo/tamper/reset")
    assert r.status_code == 303
    body = haldir_client.get("/demo/tamper").data.decode()
    assert 'class="banner banner-ok"' in body
    assert "TAMPERED" not in body


# ── Cryptographic correctness (not just visual) ─────────────────────

def _extract_json_block(body: str, anchor: str) -> dict:
    """Pull a JSON object out of the rendered page by finding the <pre>
    block that follows a given section <h2>. HTML-entity-decode first."""
    import html
    decoded = html.unescape(body)
    # Very narrow: find the <pre>...</pre> block whose nearest preceding
    # <h2> contains `anchor`. Good enough for a structured template.
    pattern = re.compile(
        r"<h2>[^<]*" + re.escape(anchor) + r"[^<]*<.*?<pre>(.*?)</pre>",
        re.DOTALL,
    )
    m = pattern.search(decoded)
    assert m, f"could not find pre-block for anchor {anchor!r}"
    return json.loads(m.group(1))


def test_rendered_proof_actually_verifies_in_untampered_state(
    haldir_client,
) -> None:
    """The demo must be honest — the rendered inclusion proof has to
    verify against the rendered STH root, not just visually claim to."""
    import haldir_merkle as merkle
    haldir_client.post("/demo/tamper/reset")
    body = haldir_client.get("/demo/tamper").data.decode()
    sth = _extract_json_block(body, "Live Signed Tree Head")
    proof = _extract_json_block(body, "Inclusion proof captured pre-tamper")
    # Proof self-verifies (leaf hashes up to root_hash).
    assert merkle.verify_inclusion_hex(proof)
    # And the root the proof commits to equals the live-tree root.
    assert proof["root_hash"] == sth["root_hash"]


def test_rendered_proof_fails_to_verify_post_tamper(haldir_client) -> None:
    """Post-tamper, the visitor-captured proof must fail verification
    against the live root — that's the whole claim."""
    import haldir_merkle as merkle
    haldir_client.post("/demo/tamper/reset")
    # Grab the pre-tamper proof and STH.
    pre_body = haldir_client.get("/demo/tamper").data.decode()
    pre_proof = _extract_json_block(pre_body, "Inclusion proof captured pre-tamper")
    # Now tamper.
    haldir_client.post("/demo/tamper/mutate")
    post_body = haldir_client.get("/demo/tamper").data.decode()
    post_sth = _extract_json_block(post_body, "Live Signed Tree Head")
    # The old proof is internally-consistent (it still self-verifies).
    assert merkle.verify_inclusion_hex(pre_proof)
    # But its root_hash no longer matches the live tree.
    assert pre_proof["root_hash"] != post_sth["root_hash"]
    # Clean up.
    haldir_client.post("/demo/tamper/reset")


# ── Isolation ────────────────────────────────────────────────────────

def test_demo_tenant_is_isolated() -> None:
    """Tampering the demo tenant must not mutate other tenants' logs."""
    import api
    from haldir_db import get_db
    import haldir_demo_tamper
    client = api.app.test_client()
    client.post("/demo/tamper/reset")
    client.post("/demo/tamper/mutate")

    conn = get_db(api.DB_PATH)
    try:
        other = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE tenant_id != ? "
            "AND action = ?",
            (haldir_demo_tamper.DEMO_TENANT, "stripe.refund.create"),
        ).fetchone()[0]
    finally:
        conn.close()
    # No other tenant should have gained or lost rows matching the demo
    # entry's action string.
    assert other == 0, (
        "tamper leaked into another tenant — demo is not isolated"
    )
    client.post("/demo/tamper/reset")


# ── Security: no indexing / no sensitive data ────────────────────────

def test_demo_page_is_open_to_search_engines(haldir_client) -> None:
    """Opposite of /compliance — this page is public-facing marketing.
    We WANT it indexed."""
    body = haldir_client.get("/demo/tamper").data.decode()
    # Explicit index allowance (or absence of noindex).
    assert 'content="noindex"' not in body
    assert 'content="index,follow"' in body


def test_demo_page_excluded_from_openapi() -> None:
    """HTML marketing surface — not an API."""
    import api
    from haldir_openapi import generate_openapi
    spec = generate_openapi(api.app)
    assert "/demo/tamper" not in spec["paths"]
