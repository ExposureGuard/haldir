"""
HTTP surface for encryption key management.

The rotation logic itself is proven in test_key_rotation.py. What matters
here is the boundary: who is allowed to re-key the store, that the endpoint
refuses to accept a key over the wire, and that a rotation which could not
read everything reports that rather than claiming success.

Run: python -m pytest tests/test_vault_key_api.py -v
"""

from __future__ import annotations

import base64
import json
import os
import sys
import uuid


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
from haldir_vault.vault import KEY_LEN, _seal, key_id_for  # noqa: E402


def make_key(client, admin_key, scopes, name="scoped"):
    """Mint a key with an explicit scope set. Minting requires an existing
    key, so the admin key authorizes it."""
    r = client.post(
        "/v1/keys",
        json={"name": f"{name}-{uuid.uuid4().hex[:8]}", "scopes": scopes},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert r.status_code == 201, r.data
    return r.get_json()["key"]


def auth(key):
    return {"Authorization": f"Bearer {key}"}


def rotated(response):
    """Assert a rotation was accepted, and return its report.

    This suite runs against `haldir.db`, a long-lived file in the repo root
    that every run appends to while starting from a fresh ephemeral key. Rows
    written by earlier runs are therefore permanently undecryptable, and a
    whole-vault rotation always meets some. Reporting 207 for those is the
    correct behaviour, not a fault — and that behaviour has its own test at
    the bottom of this file. What these tests are about is the secret they
    created themselves.
    """
    assert response.status_code in (200, 207), response.data
    return response.get_json()


def assert_handled(report, name):
    """The named secret was rewritten or already current — never failed."""
    assert not any(f["name"] == name for f in report["failed"]), (
        f"{name} failed to rotate: {report['failed']}"
    )
    touched = report["rotated"] + report["already_current"]
    assert any(s["name"] == name for s in touched), f"{name} was not rotated"


# ── Who may re-key the deployment ────────────────────────────────────

def test_census_requires_vault_read(haldir_client, bootstrap_key) -> None:
    k = make_key(haldir_client, bootstrap_key, ["audit:read"])
    r = haldir_client.get("/v1/vault/keys", headers=auth(k))
    assert r.status_code == 403


def test_rotating_requires_its_own_scope(haldir_client, bootstrap_key) -> None:
    """vault:write is authority over the secrets. vault:rotate is authority
    over the key that protects them. A key holding the first must not
    silently hold the second — otherwise anyone who can add a secret can
    re-key the whole deployment."""
    k = make_key(haldir_client, bootstrap_key, ["vault:read", "vault:write"])
    r = haldir_client.post("/v1/vault/rotate", headers=auth(k))
    assert r.status_code == 403, (
        "vault:write alone must not authorize re-keying the vault"
    )


def test_wildcard_key_may_rotate(haldir_client, bootstrap_key) -> None:
    report = rotated(haldir_client.post("/v1/vault/rotate?dry_run=true",
                                        headers=auth(bootstrap_key)))
    assert report["dry_run"] is True


def test_rotation_requires_authentication(haldir_client) -> None:
    assert haldir_client.post("/v1/vault/rotate").status_code == 401
    assert haldir_client.get("/v1/vault/keys").status_code == 401


# ── Census ───────────────────────────────────────────────────────────

def test_census_reports_shape(haldir_client, bootstrap_key) -> None:
    body = haldir_client.get("/v1/vault/keys", headers=auth(bootstrap_key)).get_json()
    assert set(body) >= {"keys", "blobs_by_key", "total_blobs", "unreadable_blobs"}
    assert isinstance(body["blobs_by_key"], dict)
    assert any(k["role"] == "primary" for k in body["keys"])


def test_census_never_returns_key_material(haldir_client, bootstrap_key) -> None:
    body = haldir_client.get("/v1/vault/keys", headers=auth(bootstrap_key)).get_json()
    raw = api.vault.encryption_key.decode()
    assert raw not in json.dumps(body)
    assert api.vault._raw_key.hex() not in json.dumps(body)


# ── The endpoint refuses to take a key over the wire ─────────────────

def test_a_key_in_the_request_body_is_ignored(haldir_client, bootstrap_key) -> None:
    """If this endpoint honoured a posted key, that key would land in proxy
    logs, request captures, and shell history — and the server would accept a
    key it was never configured with. It rotates to the key it was started
    with, and nothing else."""
    before = api.vault._keyring.primary_id
    attacker_key = base64.urlsafe_b64encode(os.urandom(KEY_LEN)).decode()

    rotated(haldir_client.post(
        "/v1/vault/rotate",
        json={"new_key": attacker_key, "key": attacker_key},
        headers=auth(bootstrap_key),
    ))
    assert api.vault._keyring.primary_id == before, (
        "the vault adopted a key supplied in the request body"
    )


# ── Dry run ──────────────────────────────────────────────────────────

def test_dry_run_reports_work_without_doing_it(haldir_client, bootstrap_key,
                                               fresh_counter) -> None:
    name = f"dryrun-{uuid.uuid4().hex[:8]}"
    haldir_client.post("/v1/secrets", json={"name": name, "value": "v"},
                       headers=auth(bootstrap_key))

    before = dict(api.vault.key_census()["blobs_by_key"])
    report = rotated(haldir_client.post("/v1/vault/rotate?dry_run=true",
                                        headers=auth(bootstrap_key)))
    assert report["dry_run"] is True
    assert api.vault.key_census()["blobs_by_key"] == before

    haldir_client.delete(f"/v1/secrets/{name}", headers=auth(bootstrap_key))


# ── A real rotation, end to end ──────────────────────────────────────

def test_rotation_over_http_rekeys_a_foreign_blob(haldir_client, bootstrap_key,
                                                  fresh_counter) -> None:
    """Store a secret, rewrite its ciphertext under a key the vault does not
    treat as primary, then rotate over HTTP and read it back through the API.

    This is the whole operator flow with the HTTP layer in the middle.
    """
    name = f"rotate-{uuid.uuid4().hex[:8]}"
    value = "value-that-must-survive"
    assert haldir_client.post("/v1/secrets", json={"name": name, "value": value},
                              headers=auth(bootstrap_key)).status_code == 201

    foreign = os.urandom(KEY_LEN)
    foreign_id = key_id_for(foreign)

    conn = api.get_db(api.DB_PATH)
    row = conn.execute("SELECT tenant_id, encrypted_value FROM secrets WHERE name = ?",
                       (name,)).fetchone()
    assert row is not None, "the secret was not stored where expected"
    # The tenant is derived from the API key, so read it rather than assume
    # it — the AAD binds ciphertext to (tenant, name) and a wrong tenant
    # would make the re-sealed blob unopenable for the wrong reason.
    tenant = row["tenant_id"] or ""

    # Reading a secret back requires a session holding its scope, so the
    # read-back at the end proves the value survived rotation *and* that the
    # ordinary access path still works. The session comes from the gate
    # directly rather than POST /v1/sessions: that route enforces a per-tier
    # agent cap, this shared database is well past the free tier's, and the
    # cap is not what this test is about.
    session = api.gate.create_session(
        f"rot-{uuid.uuid4().hex[:8]}", scopes=["read"], tenant_id=tenant,
    )
    session_id = session.session_id
    aad = f"{tenant}:{name}".encode()
    conn.execute("UPDATE secrets SET encrypted_value = ? WHERE name = ? AND tenant_id = ?",
                 (_seal(foreign, foreign_id, value.encode(), aad), name, tenant))
    conn.commit()
    conn.close()

    # Run as if the operator had listed the foreign key in ..._PREVIOUS.
    api.vault._keyring.others[foreign_id] = foreign
    try:
        census = haldir_client.get("/v1/vault/keys", headers=auth(bootstrap_key)).get_json()
        assert census["blobs_by_key"].get(foreign_id) == 1

        report = rotated(haldir_client.post("/v1/vault/rotate",
                                            headers=auth(bootstrap_key)))
        assert_handled(report, name)

        after = haldir_client.get("/v1/vault/keys", headers=auth(bootstrap_key)).get_json()
        assert foreign_id not in after["blobs_by_key"], (
            "a blob still names the key we just rotated away from"
        )

        got = haldir_client.get(f"/v1/secrets/{name}",
                                headers={**auth(bootstrap_key), "X-Session-ID": session_id})
        assert got.status_code == 200
        assert got.get_json()["value"] == value
    finally:
        api.vault._keyring.others.pop(foreign_id, None)
        api.vault._secrets.pop(f"{tenant}:{name}", None)
        haldir_client.delete(f"/v1/secrets/{name}", headers=auth(bootstrap_key))


# ── Partial failure is reported, not swallowed ───────────────────────

def test_a_secret_that_cannot_be_read_makes_the_rotation_report_failure(
    haldir_client, bootstrap_key
) -> None:
    """207, not 200. An operator who is told "rotated" and later finds a
    secret they can no longer read has lost data to a green checkmark."""
    name = f"orphan-{uuid.uuid4().hex[:8]}"
    orphan_key = os.urandom(KEY_LEN)
    tenant = api.vault._stored_secrets()[0][0] if api.vault._stored_secrets() else ""
    conn = api.get_db(api.DB_PATH)
    conn.execute(
        "INSERT INTO secrets (name, tenant_id, encrypted_value, scope_required, created_at, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (name, tenant,
         _seal(orphan_key, key_id_for(orphan_key), b"unreachable", f"{tenant}:{name}".encode()),
         "read", 0.0, "{}"))
    conn.commit()
    conn.close()

    try:
        r = haldir_client.post("/v1/vault/rotate", headers=auth(bootstrap_key))
        assert r.status_code == 207, r.data
        report = r.get_json()
        assert report["summary"]["failed"] >= 1
        assert any(f["name"] == name for f in report["failed"])
    finally:
        api.vault._secrets.pop(f"{tenant}:{name}", None)
        conn = api.get_db(api.DB_PATH)
        conn.execute("DELETE FROM secrets WHERE name = ? AND tenant_id = ?", (name, "default"))
        conn.commit()
        conn.close()
