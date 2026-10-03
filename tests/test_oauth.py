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
