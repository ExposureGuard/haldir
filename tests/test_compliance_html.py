"""
Tests for the live web compliance dashboard at /compliance.

Mirror of test_admin_html — same auth flow + same demo path + same
noindex hygiene, but rendering the evidence-pack HTML.

Run: python -m pytest tests/test_compliance_html.py -v
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Login surface ────────────────────────────────────────────────────

def test_no_key_renders_login_form(haldir_client) -> None:
    r = haldir_client.get("/compliance")
    assert r.status_code == 200
    body = r.data.decode()
    # Reuses the admin login form.
    assert "Sign in" in body
    assert "Live demo" in body


def test_invalid_key_returns_401_with_form(haldir_client) -> None:
    r = haldir_client.get("/compliance?key=hld_definitely_not_valid")
    assert r.status_code == 401
    assert "Invalid" in r.data.decode() or "invalid" in r.data.decode().lower()


# ── Live render ──────────────────────────────────────────────────────

def test_valid_key_renders_evidence_pack(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(f"/compliance?key={bootstrap_key}")
    assert r.status_code == 200
    body = r.data.decode()

    # Top chrome.
    assert "Haldir compliance evidence" in body
    # Eight section headers all present.
    for hdr in (
        "1 · Identity",
        "2 · Access control",
        "3 · Encryption",
        "4 · Audit trail",
        "5 · Spend governance",
        "6 · Human approvals",
        "7 · Outbound alerting",
        "8 · Document signature",
    ):
        assert hdr in body, f"missing section header {hdr!r}"
    # SOC2 control codes rendered.
    for cc in ("CC6.1", "CC6.7", "CC7.2", "CC5.2", "CC8.1", "CC7.3"):
        assert cc in body, f"missing SOC2 criterion {cc!r}"
    # Markdown download CTA.
    assert "Download Markdown" in body


def test_dashboard_marked_noindex(haldir_client, bootstrap_key) -> None:
    """Compliance pages contain tenant-scoped data + the API key in
    URLs. Search engines must not index them even on accidental link
    leak."""
    r = haldir_client.get(f"/compliance?key={bootstrap_key}")
    body = r.data.decode()
    assert 'name="robots"' in body
    assert "noindex" in body


def test_authorization_header_works_too(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(
        "/compliance",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    assert "Haldir compliance evidence" in r.data.decode()


# ── Demo flow ────────────────────────────────────────────────────────

def test_demo_flow_mints_and_redirects(haldir_client) -> None:
    r = haldir_client.get("/compliance?demo=1")
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert "/compliance?key=hld_" in loc
    minted = loc.split("key=")[1]
    r2 = haldir_client.get(f"/compliance?key={minted}")
    assert r2.status_code == 200
    assert "Haldir compliance evidence" in r2.data.decode()


# ── OpenAPI exclusion ────────────────────────────────────────────────

def test_compliance_html_excluded_from_openapi() -> None:
    import api
    from haldir_openapi import generate_openapi
    spec = generate_openapi(api.app)
    # HTML route excluded.
    assert "/compliance" not in spec["paths"]
    # JSON sibling stays in the spec for SDK consumers.
    assert "/v1/compliance/evidence" in spec["paths"]
