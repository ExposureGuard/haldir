"""Whose address is this, really.

`haldir_client_ip` chooses between a signed claim from the trusted edge and the
socket peer. Production made this necessary: behind Cloudflare -> Railway the
socket peer is a *rotating* internal address (100.64.0.6/.14/.17/.22 in one
burst of production logs), so every per-IP limit keyed on it collapsed into a
handful of shared buckets the whole internet rotated through.

The property that matters: with no secret configured, nothing changes. Every
request resolves to exactly what it resolved to before this module existed.

Run: python -m pytest tests/test_client_ip.py -v
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
import haldir_client_ip  # noqa: E402

SECRET = "origin-secret-for-tests"
FALLBACK = "100.64.0.22"


class _Request:
    """The two attributes the resolver reads — nothing Flask-specific."""

    def __init__(self, headers=None, remote_addr=FALLBACK):
        self.headers = headers or {}
        self.remote_addr = remote_addr


def _headers(secret=None, ip=None) -> dict:
    out: dict[str, str] = {}
    if secret is not None:
        out[haldir_client_ip.ORIGIN_SECRET_HEADER] = secret
    if ip is not None:
        out[haldir_client_ip.CLIENT_IP_HEADER] = ip
    return out


# ── No secret: behaviour identical to before this module existed ────────

def test_no_secret_configured_means_headers_are_ignored(monkeypatch) -> None:
    monkeypatch.delenv(haldir_client_ip.ORIGIN_SECRET_ENV, raising=False)
    r = _Request(_headers(secret=SECRET, ip="203.0.113.7"))
    assert haldir_client_ip.client_ip(r) == FALLBACK


def test_an_empty_secret_is_not_a_secret(monkeypatch) -> None:
    """`HALDIR_ORIGIN_SECRET=""` in an env file must not turn "present an
    empty header" into a match."""
    monkeypatch.setenv(haldir_client_ip.ORIGIN_SECRET_ENV, "")
    r = _Request(_headers(secret="", ip="203.0.113.7"))
    assert haldir_client_ip.client_ip(r) == FALLBACK


# ── A secret is configured: trust is earned, not assumed ────────────────

def test_a_signed_claim_is_used(monkeypatch) -> None:
    monkeypatch.setenv(haldir_client_ip.ORIGIN_SECRET_ENV, SECRET)
    r = _Request(_headers(secret=SECRET, ip="203.0.113.7"))
    assert haldir_client_ip.client_ip(r) == "203.0.113.7"


def test_a_wrong_secret_falls_back_to_the_socket_peer(monkeypatch) -> None:
    """This is the direct-to-Railway path: both headers are caller-supplied
    there, so an unverifiable claim must buy nothing."""
    monkeypatch.setenv(haldir_client_ip.ORIGIN_SECRET_ENV, SECRET)
    r = _Request(_headers(secret="not-the-secret", ip="203.0.113.7"))
    assert haldir_client_ip.client_ip(r) == FALLBACK


def test_a_missing_claim_falls_back(monkeypatch) -> None:
    monkeypatch.setenv(haldir_client_ip.ORIGIN_SECRET_ENV, SECRET)
    r = _Request(_headers(secret=SECRET))
    assert haldir_client_ip.client_ip(r) == FALLBACK


def test_a_signed_claim_that_is_not_an_address_falls_back(monkeypatch) -> None:
    monkeypatch.setenv(haldir_client_ip.ORIGIN_SECRET_ENV, SECRET)
    r = _Request(_headers(secret=SECRET, ip="not-an-ip; DROP TABLE"))
    assert haldir_client_ip.client_ip(r) == FALLBACK


def test_an_ipv6_claim_is_normalised(monkeypatch) -> None:
    monkeypatch.setenv(haldir_client_ip.ORIGIN_SECRET_ENV, SECRET)
    r = _Request(_headers(secret=SECRET, ip="2001:0db8:0000:0000:0000:0000:0000:0001"))
    assert haldir_client_ip.client_ip(r) == "2001:db8::1"


def test_surrounding_whitespace_in_the_claim_is_tolerated(monkeypatch) -> None:
    monkeypatch.setenv(haldir_client_ip.ORIGIN_SECRET_ENV, SECRET)
    r = _Request(_headers(secret=SECRET, ip=" 203.0.113.7 "))
    assert haldir_client_ip.client_ip(r) == "203.0.113.7"


# ── The app is wired to the resolver, not to remote_addr directly ───────

def test_the_oauth_limits_read_the_resolved_address(monkeypatch) -> None:
    """`_oauth_ip` is what the registration and account-creation limits key
    on; it must be the resolved value, or the fix is inert."""
    monkeypatch.setenv(haldir_client_ip.ORIGIN_SECRET_ENV, SECRET)
    with api.app.test_request_context(
        "/",
        headers={
            haldir_client_ip.ORIGIN_SECRET_HEADER: SECRET,
            haldir_client_ip.CLIENT_IP_HEADER: "203.0.113.7",
        },
        environ_base={"REMOTE_ADDR": FALLBACK},
    ):
        assert api._oauth_ip() == "203.0.113.7"
