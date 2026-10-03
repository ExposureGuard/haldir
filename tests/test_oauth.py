"""OAuth: the audience binding, and everything that depends on it.

Migration 009 adds `api_keys.oauth_resource` and `api_keys.oauth_client_id`.
Nothing in this repository sets them yet — the authorization endpoints land
next — so these tests write the columns directly and assert what `/mcp` does
with them.

The property that matters most is the negative one. Every key in existence is
unbound, so "a key with no binding still works" is the assertion that keeps
this change from breaking every client that already connects. The positive
assertions below only mean something because that one passes.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
from haldir_db import get_db  # noqa: E402
from haldir_public_url import public_base_url  # noqa: E402


def _make_key(client, admin_key: str, name: str = "audience") -> str:
    import uuid

    r = client.post(
        "/v1/keys",
        json={"name": f"{name}-{uuid.uuid4().hex[:8]}"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert r.status_code == 201, r.data
    return r.get_json()["key"]


def _bind(key: str, resource: str, client_id: str = "test-client") -> None:
    """Write the OAuth columns the way the authorization endpoint eventually will."""
    conn = get_db(api.DB_PATH)
    try:
        conn.execute(
            "UPDATE api_keys SET oauth_resource = ?, oauth_client_id = ? "
            "WHERE key_hash = ?",
            (resource, client_id, api._hash_key(key)),
        )
        conn.commit()
    finally:
        conn.close()


def _mcp_call(client, key: str):
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {key}"},
    )


# ── The property that protects every existing client ────────────────────

def test_a_key_with_no_binding_is_not_restricted(haldir_client, bootstrap_key) -> None:
    """Unbound is the shape of every key that exists. This must never change."""
    assert _mcp_call(haldir_client, bootstrap_key).status_code == 200


def test_the_unbound_key_still_reaches_the_rest_of_the_api(
    haldir_client, bootstrap_key
) -> None:
    """The binding is a /mcp rule, not a general one — /v1 is untouched."""
    r = haldir_client.get(
        "/v1/usage", headers={"Authorization": f"Bearer {bootstrap_key}"}
    )
    assert r.status_code == 200


# ── And the check itself ────────────────────────────────────────────────

def test_a_key_bound_to_this_server_is_accepted(haldir_client, bootstrap_key) -> None:
    key = _make_key(haldir_client, bootstrap_key)
    _bind(key, f"{public_base_url().rstrip('/')}/mcp")
    assert _mcp_call(haldir_client, key).status_code == 200


def test_a_key_bound_to_a_different_resource_is_refused(
    haldir_client, bootstrap_key
) -> None:
    """A token issued for another server must not be usable at this one.

    This is the MCP requirement that /mcp validate a token was issued for it,
    applied narrowly: only keys that name a resource are held to it.
    """
    key = _make_key(haldir_client, bootstrap_key)
    _bind(key, "https://somewhere-else.example/mcp")

    r = _mcp_call(haldir_client, key)
    assert r.status_code == 401
    body = r.get_json()
    assert body["error"]["code"] == -32001
    assert "not issued for this server" in body["error"]["message"]


def test_the_binding_does_not_block_the_rest_of_the_api(
    haldir_client, bootstrap_key
) -> None:
    """A bound key is refused at /mcp and still works everywhere else.

    Pinned deliberately: the alternative — refusing it globally — would look
    like the stricter choice and would break `haldir` itself the moment a
    connector's key was used from the CLI.
    """
    key = _make_key(haldir_client, bootstrap_key)
    _bind(key, "https://somewhere-else.example/mcp")

    assert _mcp_call(haldir_client, key).status_code == 401
    r = haldir_client.get("/v1/usage", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200


@pytest.mark.parametrize(
    "resource",
    ["https://haldir.xyz", "https://haldir.xyz/"],
)
def test_both_spellings_of_the_canonical_uri_are_accepted(
    haldir_client, bootstrap_key, resource: str
) -> None:
    """RFC 8707's canonical URI is valid with and without the path, and clients
    differ on which they send. A server that accepts only one rejects half its
    callers for no security benefit."""
    key = _make_key(haldir_client, bootstrap_key)
    _bind(key, resource)
    assert _mcp_call(haldir_client, key).status_code == 200


# ── The authorization-code flow ──────────────────────────────────────
#
# Everything below drives the real endpoints through the test client. The
# per-IP limits are real limits, so the OAuth tables are emptied between tests —
# otherwise the sixth test in this file would be the one that discovers the
# daily cap, and it would look like a bug in the flow.

import threading  # noqa: E402

REDIRECT = "https://client.example/cb"


@pytest.fixture(autouse=True)
def _clean_oauth_state():
    from haldir_db import get_db

    conn = get_db(api.DB_PATH)
    try:
        conn.execute("DELETE FROM oauth_codes")
        conn.execute("DELETE FROM oauth_clients")
        conn.commit()
    finally:
        conn.close()
    api._oauth_bursts.clear()
    yield


def _register(client, name="Test Client", redirect_uris=(REDIRECT,)):
    r = client.post(
        "/oauth/register",
        json={"client_name": name, "redirect_uris": list(redirect_uris)},
    )
    assert r.status_code == 201, r.data
    return r.get_json()


def _verifier() -> str:
    import secrets as _s

    return _s.token_urlsafe(48)


def _authorize(client, client_id, redirect_uri=REDIRECT, verifier=None,
               challenge=None, method="S256", resource=None, state="xyz"):
    # A test that only checks a refusal still has to send a well-formed request,
    # so mint a verifier when the caller does not need to keep one.
    challenge = challenge if challenge is not None else haldir_oauth.pkce_challenge_for(
        verifier or _verifier()
    )
    return client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": method,
            "state": state,
            "resource": resource or haldir_oauth.resource(),
        },
    )


def _token(client, client_id, code, verifier, redirect_uri=REDIRECT, resource=None):
    return client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "resource": resource or haldir_oauth.resource(),
        },
    )


import haldir_oauth  # noqa: E402


def test_the_happy_path_mints_a_key_that_works_here_and_there(haldir_client) -> None:
    """Register → consent → code → token, and the token is a working key.

    Both surfaces, deliberately: "works at /mcp" is the feature, and "works at
    /v1/*" is the decision that made the token an ordinary key. A future change
    that quietly made this a /mcp-only credential would fail here.
    """
    client = _register(haldir_client)
    verifier = _verifier()

    page = haldir_client.get("/oauth/authorize", query_string={
        "response_type": "code", "client_id": client["client_id"],
        "redirect_uri": REDIRECT,
        "code_challenge": haldir_oauth.pkce_challenge_for(verifier),
        "code_challenge_method": "S256", "state": "xyz",
    })
    assert page.status_code == 200
    assert b"Test Client" in page.data

    consent = _authorize(haldir_client, client["client_id"], verifier=verifier)
    assert consent.status_code == 302
    location = consent.headers["Location"]
    assert location.startswith(REDIRECT)
    assert "iss=" in location and "state=xyz" in location
    code = location.split("code=")[1].split("&")[0]

    tok = _token(haldir_client, client["client_id"], code, verifier)
    assert tok.status_code == 200, tok.data
    key = tok.get_json()["access_token"]
    assert key.startswith("hld_")
    assert tok.headers.get("Cache-Control") == "no-store"

    mcp = haldir_client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert mcp.status_code == 200, mcp.data

    api_call = haldir_client.get(
        "/v1/usage", headers={"Authorization": f"Bearer {key}"}
    )
    assert api_call.status_code == 200


def test_a_code_cannot_be_redeemed_twice(haldir_client) -> None:
    client = _register(haldir_client)
    verifier = _verifier()
    code = _authorize(
        haldir_client, client["client_id"], verifier=verifier
    ).headers["Location"].split("code=")[1].split("&")[0]

    first = _token(haldir_client, client["client_id"], code, verifier)
    assert first.status_code == 200

    second = _token(haldir_client, client["client_id"], code, verifier)
    assert second.status_code == 400
    assert second.get_json()["error"] == "invalid_grant"


def test_two_threads_cannot_both_redeem_one_code(haldir_client) -> None:
    """The race the atomic UPDATE exists for.

    Production runs two gunicorn workers, so this is not hypothetical: a
    SELECT-then-UPDATE lets both requests see an unused code and both mint a
    key. The claim is guarded on `used_at = 0` and lands in one statement, so
    exactly one caller can observe rowcount 1.
    """
    client = _register(haldir_client)
    verifier = _verifier()
    code = _authorize(
        haldir_client, client["client_id"], verifier=verifier
    ).headers["Location"].split("code=")[1].split("&")[0]

    results: list[int] = []
    lock = threading.Lock()

    def redeem() -> None:
        r = _token(haldir_client, client["client_id"], code, verifier)
        with lock:
            results.append(r.status_code)

    threads = [threading.Thread(target=redeem) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(200) == 1, f"expected exactly one winner, got {results}"


def test_a_wrong_verifier_burns_the_code(haldir_client) -> None:
    """A refused exchange must not leave the code live.

    Otherwise a guess costs the attacker nothing and the window stays open —
    so the claim happens before the verifier is checked, and the second attempt
    fails even with the right one.
    """
    client = _register(haldir_client)
    verifier = _verifier()
    code = _authorize(
        haldir_client, client["client_id"], verifier=verifier
    ).headers["Location"].split("code=")[1].split("&")[0]

    wrong = _token(haldir_client, client["client_id"], code, _verifier())
    assert wrong.status_code == 400
    assert wrong.get_json()["error"] == "invalid_grant"

    retry = _token(haldir_client, client["client_id"], code, verifier)
    assert retry.status_code == 400, "the code was still redeemable after a failure"


def test_plain_pkce_is_refused(haldir_client) -> None:
    client = _register(haldir_client)
    r = _authorize(
        haldir_client, client["client_id"],
        challenge=_verifier(), method="plain",
    )
    # A page, not a JSON error: this is a browser form post, and the person who
    # submitted it is the one who has to read the result.
    assert r.status_code == 400
    assert b"invalid_request" in r.data


@pytest.mark.parametrize("uri", [
    "https://elsewhere.example/cb",       # never registered
    "https://client.example/cb/",         # trailing slash is a different string
    "https://client.example/cb#frag",     # fragments are forbidden outright
    "http://localhost.evil.com/cb",       # a loopback-looking name that is not one
    "http://evil.example\\@localhost/cb",  # WHATWG parses this as evil.example
    "https://client.example:8443/cb",     # a different port on a non-loopback host
])
def test_a_redirect_uri_that_does_not_match_is_never_redirected_to(
    haldir_client, uri: str
) -> None:
    """Refused, with no Location header.

    The assertion that matters is the absence of a redirect: an error returned
    *by redirecting to the bad URI* is the open redirect, and it is the mistake
    this test exists to make impossible.
    """
    client = _register(haldir_client)
    r = _authorize(haldir_client, client["client_id"], redirect_uri=uri)
    assert r.status_code == 400
    assert "Location" not in r.headers


def test_a_loopback_redirect_may_vary_its_port(haldir_client) -> None:
    """RFC 8252 §7.3, and without it a native client cannot connect at all.

    A desktop client picks its callback port at runtime, so requiring an exact
    match on `http://localhost:PORT/cb` would force a re-registration per run.
    """
    client = _register(haldir_client, redirect_uris=("http://localhost/cb",))
    verifier = _verifier()
    r = _authorize(
        haldir_client, client["client_id"], verifier=verifier,
        redirect_uri="http://localhost:52813/cb",
    )
    assert r.status_code == 302
    assert r.headers["Location"].startswith("http://localhost:52813/cb")


def test_the_consent_page_escapes_what_a_stranger_supplied(haldir_client) -> None:
    """Registration is anonymous, and this page shares an origin with the
    dashboard — whose links carry the API key in the query string. An
    unescaped interpolation here is a script running beside a credential."""
    client = _register(haldir_client, name='<script>alert(1)</script>')
    verifier = _verifier()
    r = haldir_client.get("/oauth/authorize", query_string={
        "response_type": "code", "client_id": client["client_id"],
        "redirect_uri": REDIRECT,
        "code_challenge": haldir_oauth.pkce_challenge_for(verifier),
        "code_challenge_method": "S256",
    })
    assert r.status_code == 200
    assert b"<script>alert(1)</script>" not in r.data
    assert b"&lt;script&gt;" in r.data
    assert "form-action 'self'" in r.headers.get("Content-Security-Policy", "")


def test_the_consent_page_cannot_be_framed(haldir_client) -> None:
    client = _register(haldir_client)
    verifier = _verifier()
    r = haldir_client.get("/oauth/authorize", query_string={
        "response_type": "code", "client_id": client["client_id"],
        "redirect_uri": REDIRECT,
        "code_challenge": haldir_oauth.pkce_challenge_for(verifier),
        "code_challenge_method": "S256",
    })
    assert r.headers.get("X-Frame-Options") == "DENY"


def test_no_oauth_response_sets_a_cookie(haldir_client) -> None:
    """Pinned to stop a future well-meaning "CSRF fix".

    This flow has no session on purpose: the consent POST creates a *new*
    account, so there is no ambient authority to forge and nothing for CSRF to
    protect. Adding a cookie would introduce exactly that authority.
    """
    client = _register(haldir_client)
    verifier = _verifier()
    responses = [
        _authorize,  # the POST that mints
    ]
    consent = _authorize(haldir_client, client["client_id"], verifier=verifier)
    page = haldir_client.get("/oauth/authorize", query_string={
        "response_type": "code", "client_id": client["client_id"],
        "redirect_uri": REDIRECT,
        "code_challenge": haldir_oauth.pkce_challenge_for(verifier),
        "code_challenge_method": "S256",
    })
    for r in (consent, page):
        assert "Set-Cookie" not in r.headers


def test_a_foreign_resource_is_refused(haldir_client) -> None:
    client = _register(haldir_client)
    verifier = _verifier()
    # GET, because this is the client waiting on a response: an error is
    # returned to it through the redirect it is already watching.
    r = haldir_client.get("/oauth/authorize", query_string={
        "response_type": "code",
        "client_id": client["client_id"],
        "redirect_uri": REDIRECT,
        "code_challenge": haldir_oauth.pkce_challenge_for(verifier),
        "code_challenge_method": "S256",
        "resource": "https://somewhere-else.example/mcp",
    })
    assert r.status_code == 302
    assert "error=invalid_target" in r.headers["Location"]


def test_an_unknown_client_is_refused_without_a_redirect(haldir_client) -> None:
    verifier = _verifier()
    r = _authorize(haldir_client, "not-a-registered-client", verifier=verifier)
    assert r.status_code == 401
    assert "Location" not in r.headers


def test_the_daily_grant_cap_bites(haldir_client) -> None:
    """The cap that stops a script farming free allowances.

    Each tenant carries its own free allowance, so an uncapped mint is uncapped
    free capacity — the shape /v1/demo/key already has and this must not copy.
    """
    client = _register(haldir_client)
    for _ in range(haldir_oauth.GRANTS_PER_IP_PER_DAY):
        r = _authorize(haldir_client, client["client_id"], verifier=_verifier())
        assert r.status_code == 302, r.data

    over = _authorize(haldir_client, client["client_id"], verifier=_verifier())
    assert over.status_code == 429


def test_mcp_challenges_and_the_rest_of_the_api_does_not(haldir_client) -> None:
    """The WWW-Authenticate header is a /mcp rule.

    An ordinary API client told to begin an OAuth flow when what it needs is an
    API key has been given the wrong instruction by the server, which is worse
    than being given none.
    """
    mcp = haldir_client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert mcp.status_code == 401
    assert "resource_metadata=" in mcp.headers.get("WWW-Authenticate", "")
    assert "WWW-Authenticate" in mcp.headers.get("Access-Control-Expose-Headers", "")

    api_call = haldir_client.get("/v1/usage")
    assert api_call.status_code == 401
    assert "WWW-Authenticate" not in api_call.headers


def test_the_discovery_documents_describe_routes_that_exist(haldir_client) -> None:
    """The documents are generated, so the URLs in them could still be wrong if
    the routes were renamed. This is the check that they agree."""
    prm = haldir_client.get("/.well-known/oauth-protected-resource").get_json()
    asm = haldir_client.get("/.well-known/oauth-authorization-server").get_json()

    assert prm["resource"] == haldir_oauth.resource()
    assert prm["authorization_servers"] == [haldir_oauth.issuer()]
    assert asm["issuer"] == haldir_oauth.issuer()
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["client_id_metadata_document_supported"] is False

    rules = {str(r.rule) for r in api.app.url_map.iter_rules()}
    for url in (asm["authorization_endpoint"], asm["token_endpoint"],
                asm["registration_endpoint"]):
        assert url.startswith(haldir_oauth.issuer())
        assert url[len(haldir_oauth.issuer()):] in rules, f"{url} is not a route"
