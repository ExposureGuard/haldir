"""
Tests for the web-rendered admin dashboard at /admin/overview.

Scope:
  - /admin redirects to /admin/overview
  - /admin/overview without auth shows the sign-in form (200, not 401)
  - /admin/overview with an invalid key returns 401 + the form
  - /admin/overview with a valid key renders the full dashboard
  - /admin/overview?demo=1 mints a sandbox key and 302s with it
  - The page is marked noindex so it doesn't show up in Google
  - Sensitive tenant data isn't echoed when the key is malformed

Run: python -m pytest tests/test_admin_html.py -v
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Routing ───────────────────────────────────────────────────────────

def test_admin_root_redirects_to_overview(haldir_client) -> None:
    r = haldir_client.get("/admin")
    assert r.status_code == 302
    assert "/admin/overview" in r.headers["Location"]


# ── Login surface (no auth) ──────────────────────────────────────────

def test_no_key_renders_login_form(haldir_client) -> None:
    """Visiting unauthenticated should NOT 401 — it should render the
    paste-your-key form so a curious GitHub visitor can demo without
    seeing a hostile error page."""
    r = haldir_client.get("/admin/overview")
    assert r.status_code == 200
    body = r.data.decode()
    assert "text/html" in r.content_type
    assert "Sign in" in body
    assert "Live demo" in body
    # The form posts back to itself.
    assert 'action="/admin/overview"' in body
    assert 'name="key"' in body


def test_invalid_key_returns_401_with_form(haldir_client) -> None:
    """Bad key should 401 (so monitoring tools can detect bad probes)
    AND render the friendly form (so a human gets a path forward)."""
    r = haldir_client.get("/admin/overview?key=hld_definitely_not_valid")
    assert r.status_code == 401
    body = r.data.decode()
    assert "Sign in" in body
    assert "Invalid" in body or "invalid" in body.lower()


# ── Live render (valid key) ──────────────────────────────────────────

def test_valid_key_renders_dashboard(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(f"/admin/overview?key={bootstrap_key}")
    assert r.status_code == 200
    body = r.data.decode()
    # Header chrome.
    assert "Haldir admin" in body
    # The seven dashboard rows.
    for label in (
        "Actions", "Spend", "Sessions", "Vault",
        "Audit", "Webhooks", "Approvals",
    ):
        assert label in body, f"missing row label {label!r}"
    # The status banner is one of the canonical phrasings.
    assert any(p in body for p in (
        "All systems operational",
        "Partial degradation",
        "Service disruption",
    ))


def test_dashboard_marked_noindex(haldir_client, bootstrap_key) -> None:
    """The admin dashboard contains tenant-specific data + the API key
    in URLs. Search engines shouldn't index it even if a link leaks."""
    r = haldir_client.get(f"/admin/overview?key={bootstrap_key}")
    assert 'name="robots"' in r.data.decode()
    assert 'noindex' in r.data.decode()


def test_dashboard_truncates_key_in_chrome(haldir_client, bootstrap_key) -> None:
    """The key is necessary in the refresh links but should be
    redacted in any visible chrome — defense against accidental
    screenshots."""
    r = haldir_client.get(f"/admin/overview?key={bootstrap_key}")
    body = r.data.decode()
    # The full key appears in href (refresh + JSON link), but the
    # visible "you are signed in as <prefix>...<suffix>" text shows
    # only first 8 + last 4.
    assert bootstrap_key[:8] + "..." + bootstrap_key[-4:] in body


# ── Demo-key flow ────────────────────────────────────────────────────

def test_demo_flow_mints_and_redirects(haldir_client) -> None:
    r = haldir_client.get("/admin/overview?demo=1")
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert "/admin/overview?key=hld_" in loc
    # The minted key should land us at a working dashboard.
    minted = loc.split("key=")[1]
    r2 = haldir_client.get(f"/admin/overview?key={minted}")
    assert r2.status_code == 200
    assert "Haldir admin" in r2.data.decode()


# ── Header-based auth (Authorization: Bearer ...) ────────────────────

def test_authorization_header_works_too(haldir_client, bootstrap_key) -> None:
    """API consumers may prefer the standard Bearer header over a
    querystring key. Both must work."""
    r = haldir_client.get(
        "/admin/overview",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    assert "Haldir admin" in r.data.decode()


# ── OpenAPI exclusion (HTML, not JSON surface) ───────────────────────

def test_admin_excluded_from_openapi() -> None:
    import api
    from haldir_openapi import generate_openapi
    spec = generate_openapi(api.app)
    assert "/admin" not in spec["paths"]
    assert "/admin/overview" not in spec["paths"]
    # The JSON sibling SHOULD appear (machine consumers want it).
    assert "/v1/admin/overview" in spec["paths"]
