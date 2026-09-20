"""
Webhook URLs must not be able to reach the filesystem or the internal network.

`urllib.request.urlopen` honours whatever scheme it is handed, and both
webhook delivery paths handed it a user-supplied string unchecked. The
response body was read back into the delivery record and served over the
API, so `url = "file:///etc/passwd"` read the file out.

Run: python -m pytest tests/test_outbound_url.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_outbound import UnsafeURL, safe_outbound_url  # noqa: E402


# ── The disclosure itself ────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file://localhost/etc/passwd",
    "gopher://evil.example/",
    "ftp://evil.example/x",
    "data:text/plain,hello",
])
def test_non_http_schemes_are_refused(url: str) -> None:
    """file:// is the one that actually reads a file; the rest are refused
    for the same reason — urllib will fetch them and we did not mean to
    offer a general-purpose fetcher."""
    with pytest.raises(UnsafeURL):
        safe_outbound_url(url)


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://127.0.0.1:5432/",
    "http://localhost/admin",
    "http://[::1]/",
    "http://10.0.0.5/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://0.0.0.0/",
])
def test_internal_addresses_are_refused(url: str) -> None:
    """The metadata endpoint hands out cloud instance credentials, and the
    rest are the internal network the host can route to but the user
    cannot."""
    with pytest.raises(UnsafeURL):
        safe_outbound_url(url)


def test_credentials_in_the_url_are_refused() -> None:
    """Stored in the webhook row in clear text and replayed on every
    delivery."""
    with pytest.raises(UnsafeURL):
        safe_outbound_url("https://user:pass@example.com/hook")


def test_empty_and_malformed_are_refused() -> None:
    for url in ["", "   ", "not a url", "http://", "//example.com/x"]:
        with pytest.raises(UnsafeURL):
            safe_outbound_url(url)


# ── It must not break the real thing ─────────────────────────────────

def test_a_normal_https_webhook_is_allowed() -> None:
    """The guard is worthless if it rejects the feature it protects."""
    assert safe_outbound_url("https://hooks.slack.com/services/T00/B00/xxx") \
        == "https://hooks.slack.com/services/T00/B00/xxx"


def test_a_public_ip_is_allowed() -> None:
    # 1.1.1.1 is Cloudflare's resolver — public, routable, not ours.
    assert safe_outbound_url("https://1.1.1.1/hook") == "https://1.1.1.1/hook"


def test_a_nonstandard_port_on_a_public_host_is_allowed() -> None:
    """Webhook receivers legitimately run on odd ports; the address check is
    what bounds where the request can go, not the port number."""
    assert safe_outbound_url("http://1.1.1.1:8080/hook") == "http://1.1.1.1:8080/hook"


def test_surrounding_whitespace_is_tolerated() -> None:
    assert safe_outbound_url("  https://example.com/hook  ") == "https://example.com/hook"


# ── Every address a name resolves to is checked ──────────────────────

def test_a_name_resolving_to_loopback_is_refused(monkeypatch) -> None:
    """A hostname is not a promise. `localhost` is obvious; the interesting
    case is a name that looks public and resolves inward, which is what a
    hostname-based allowlist would miss."""
    def fake_getaddrinfo(host, port, **kwargs):
        return [(2, 1, 6, "", ("127.0.0.1", port or 80))]

    monkeypatch.setattr("haldir_outbound.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsafeURL) as e:
        safe_outbound_url("https://totally-legit.example/hook")
    assert "127.0.0.1" in str(e.value)


def test_a_name_resolving_to_both_public_and_private_is_refused(monkeypatch) -> None:
    """Picking the first answer is not enough — urllib may reach either."""
    def fake_getaddrinfo(host, port, **kwargs):
        return [
            (2, 1, 6, "", ("93.184.216.34", port or 80)),   # public
            (2, 1, 6, "", ("169.254.169.254", port or 80)),  # metadata
        ]

    monkeypatch.setattr("haldir_outbound.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsafeURL) as e:
        safe_outbound_url("https://split.example/hook")
    assert "169.254.169.254" in str(e.value)


def test_an_unresolvable_host_is_refused_not_crashed(monkeypatch) -> None:
    import socket as _socket

    def fake_getaddrinfo(host, port, **kwargs):
        raise _socket.gaierror("Name or service not known")

    monkeypatch.setattr("haldir_outbound.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsafeURL):
        safe_outbound_url("https://does-not-exist.invalid/hook")


# ── Through the API, which is where it actually mattered ─────────────

def test_registering_a_file_url_is_refused(haldir_client, bootstrap_key) -> None:
    """The disclosure, end to end.

    A guard module that nothing calls protects nothing. This is the request
    that used to succeed: register a `file://` webhook, fire any event, and
    read the file out of the delivery record's response excerpt.
    """
    r = haldir_client.post(
        "/v1/webhooks",
        json={"url": "file:///etc/passwd", "events": ["audit.flagged"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400, (
        f"registering a file:// webhook returned {r.status_code}; it must be "
        f"refused, not accepted"
    )
    assert r.get_json().get("code") == "unsafe_url"


def test_registering_the_metadata_endpoint_is_refused(haldir_client, bootstrap_key) -> None:
    """169.254.169.254 hands out cloud instance credentials to anything that
    can reach it, and the webhook delivery record would carry the response."""
    r = haldir_client.post(
        "/v1/webhooks",
        json={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400


def test_a_refused_webhook_is_not_a_server_error(haldir_client, bootstrap_key) -> None:
    """A rejected URL is the caller's mistake. Returning 500 leaks a
    traceback, tells the caller nothing, and pages whoever is on call."""
    r = haldir_client.post(
        "/v1/webhooks",
        json={"url": "file:///etc/shadow"},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code < 500, f"refused URL produced {r.status_code}"
    body = r.get_json()
    assert "error" in body and body["error"]
    # The refusal should name the problem, not just say "bad request".
    assert "scheme" in body["error"].lower()
