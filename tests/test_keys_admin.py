"""
Tests for the API key admin lifecycle:
  GET    /v1/keys             list keys for the authed tenant
  DELETE /v1/keys/<prefix>    revoke by prefix

Scope:
  - List returns rows the tenant owns + nothing else
  - Full key value never appears in list responses
  - Revoke flips the row's revoked flag, removes auth privilege
  - Revoking a missing prefix returns 404
  - Revoke is tenant-scoped (can't revoke someone else's key)
  - Both endpoints are admin:read / admin:write gated

Run: python -m pytest tests/test_keys_admin.py -v
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── List ─────────────────────────────────────────────────────────────

def test_list_returns_at_least_the_bootstrap_key(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(
        "/v1/keys",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert "keys" in body
    assert body["count"] >= 1
    # The bootstrap key's prefix is its first 12 chars.
    prefixes = [k["prefix"] for k in body["keys"]]
    assert bootstrap_key[:12] in prefixes


def test_list_response_never_includes_full_key(haldir_client, bootstrap_key) -> None:
    """Defense in depth: the listing endpoint must never echo the
    full key. Once minted, it lives only on the holder's machine."""
    r = haldir_client.get(
        "/v1/keys",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    body = r.get_json()
    # No row should carry a `key` field; only `prefix`.
    for k in body["keys"]:
        assert "key" not in k
        # And nothing in the row should accidentally contain the full
        # bootstrap_key string.
        for v in k.values():
            assert bootstrap_key not in str(v)


def test_list_includes_scopes(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(
        "/v1/keys",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    body = r.get_json()
    for k in body["keys"]:
        assert "scopes" in k
        assert isinstance(k["scopes"], list)


def test_list_requires_admin_read_scope(haldir_client, bootstrap_key) -> None:
    """A key without admin:read should NOT be able to enumerate."""
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "narrow-list-test", "scopes": ["audit:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    narrow = r.get_json()["key"]
    r2 = haldir_client.get(
        "/v1/keys",
        headers={"Authorization": f"Bearer {narrow}"},
    )
    assert r2.status_code == 403
    assert r2.get_json()["required"] == "admin:read"


# ── Revoke ──────────────────────────────────────────────────────────

def _mint(haldir_client, bootstrap_key, name: str) -> dict:
    r = haldir_client.post(
        "/v1/keys",
        json={"name": name},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 201
    return r.get_json()


def test_revoke_flips_state_and_invalidates_auth(haldir_client, bootstrap_key) -> None:
    minted = _mint(haldir_client, bootstrap_key, "revoke-target")
    new_key = minted["key"]
    new_prefix = minted["prefix"]

    # Sanity: the new key authenticates.
    r0 = haldir_client.get("/v1/audit?limit=1",
                           headers={"Authorization": f"Bearer {new_key}"})
    assert r0.status_code == 200

    # Revoke via the bootstrap key (admin:write).
    r1 = haldir_client.delete(
        f"/v1/keys/{new_prefix}",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r1.status_code == 200
    assert r1.get_json()["revoked"] is True

    # Authentication with the revoked key now fails (401).
    r2 = haldir_client.get("/v1/audit?limit=1",
                           headers={"Authorization": f"Bearer {new_key}"})
    assert r2.status_code == 401


def test_revoke_unknown_prefix_returns_404(haldir_client, bootstrap_key) -> None:
    r = haldir_client.delete(
        "/v1/keys/hld_doesnotexist",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 404
    assert r.get_json()["code"] == "not_found"


def test_revoke_requires_admin_write_scope(haldir_client, bootstrap_key) -> None:
    """A key without admin:write must NOT be able to revoke."""
    minted = _mint(haldir_client, bootstrap_key, "revoke-scope-test")
    target_prefix = minted["prefix"]

    r = haldir_client.post(
        "/v1/keys",
        json={"name": "ro-revoker", "scopes": ["admin:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    ro_key = r.get_json()["key"]
    r2 = haldir_client.delete(
        f"/v1/keys/{target_prefix}",
        headers={"Authorization": f"Bearer {ro_key}"},
    )
    assert r2.status_code == 403
    assert r2.get_json()["required"] == "admin:write"


def test_revoked_key_appears_in_list_with_revoked_true(haldir_client, bootstrap_key) -> None:
    minted = _mint(haldir_client, bootstrap_key, "revoke-listing-test")
    haldir_client.delete(
        f"/v1/keys/{minted['prefix']}",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    r = haldir_client.get(
        "/v1/keys",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    rows = {k["prefix"]: k for k in r.get_json()["keys"]}
    assert rows[minted["prefix"]]["revoked"] is True
