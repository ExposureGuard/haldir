"""
The secrets claim, asserted as a property.

"A secret is readable only by the key, tenant, and scope entitled to it" is a
statement about all four of those axes at once. Example tests tend to fix
three and vary one, which is how a hole on an axis nobody varied survives: the
existing suite checked a wrong *key* thoroughly and had nothing to say about a
wrong tenant on a rotated entry.

AES-256-GCM with the (tenant, name) pair as associated data makes all of this
true by construction — these tests exist to confirm the construction is
actually being used, on every path, including the ones added later.

Run: python -m pytest tests/test_invariants_secrets.py -v
"""

from __future__ import annotations

import os
import sys

import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import HealthCheck, given, settings, strategies as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_db import init_db, get_db  # noqa: E402
from haldir_gate import Gate  # noqa: E402
from haldir_vault import Vault  # noqa: E402
from haldir_vault.vault import SecretEntry  # noqa: E402


_SETTINGS = settings(
    max_examples=50, deadline=None,
    suppress_health_check=[
        HealthCheck.too_slow,
        # Deliberate: `db` initialises the schema once per test and every
        # example then writes its own secret under its own name and tenant.
        # The generated values are the point — a fresh database per example
        # would re-run the whole migration for no added isolation.
        HealthCheck.function_scoped_fixture,
    ],
)

names = st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126),
                min_size=1, max_size=32)
tenants = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
                  min_size=1, max_size=16)
# Printable ASCII plus a few characters that must survive JSON and byte
# handling. Values are secrets, so length varies and Unicode is fair game.
values = st.text(min_size=1, max_size=200)


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "secrets.db")
    init_db(path)

    # Empty the secrets table.
    #
    # On SQLite this path is a fresh file and there is nothing to clear. On
    # Postgres DATABASE_URL wins and every run shares one table, so rows from
    # earlier runs are still there — encrypted under random keys that were
    # never persisted anywhere. A rotation re-keys the whole deployment, tries
    # to read those rows, and fails on them, which is correct behaviour for
    # the code and noise for this test.
    from haldir_db import get_db
    conn = get_db(path)
    try:
        conn.execute("DELETE FROM secrets")
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        conn.close()
    return path


# ── The three axes, varied together ──────────────────────────────────

@given(name=names, tenant=tenants, value=values)
@_SETTINGS
def test_a_secret_moves_only_between_its_own_name_tenant_and_key(
    db, name: str, tenant: str, value: str
) -> None:
    """The central property: change any one of the three bindings and the
    ciphertext must stop opening.

    Swapping ciphertext between rows is the attack a database-level intruder
    with no key has — reading is denied to them, but *moving* a row might
    still be useful if the binding is missing.
    """
    v = Vault(encryption_key=Vault.generate_key(), db_path=db)
    entry = v.store_secret(name, value, tenant_id=tenant)
    blob = entry.encrypted_value

    # Right name, right tenant, right key — opens.
    assert v.get_secret(name, tenant_id=tenant) == value

    # Wrong key, everything else right.
    stranger = Vault(encryption_key=Vault.generate_key(), db_path=db)
    stranger._secrets[f"{tenant}:{name}"] = SecretEntry(
        name=name, encrypted_value=blob, tenant_id=tenant)
    with pytest.raises((InvalidTag, ValueError)):
        stranger.get_secret(name, tenant_id=tenant)

    # Right key, wrong tenant.
    v._secrets[f"{tenant}-other:{name}"] = SecretEntry(
        name=name, encrypted_value=blob, tenant_id=f"{tenant}-other")
    with pytest.raises((InvalidTag, ValueError)):
        v.get_secret(name, tenant_id=f"{tenant}-other")

    # Right key, right tenant, different name.
    v._secrets[f"{tenant}:{name}-other"] = SecretEntry(
        name=f"{name}-other", encrypted_value=blob, tenant_id=tenant)
    with pytest.raises((InvalidTag, ValueError)):
        v.get_secret(f"{name}-other", tenant_id=tenant)


@given(name=names, value=values)
@_SETTINGS
def test_the_plaintext_never_reaches_storage(db, name: str, value: str) -> None:
    """The row must not contain the secret. This is the claim a customer is
    actually making when they say "the model never sees it"."""
    v = Vault(encryption_key=Vault.generate_key(), db_path=db)
    v.store_secret(name, value, tenant_id="t")

    conn = get_db(db)
    row = conn.execute("SELECT * FROM secrets WHERE name = ?", (name,)).fetchone()
    conn.close()

    blob = bytes(row["encrypted_value"])
    if len(value) >= 4:
        assert value.encode() not in blob, (
            f"the stored ciphertext contains the plaintext {value!r}"
        )


@given(value=values)
@_SETTINGS
def test_encrypting_twice_never_reuses_a_nonce(db, value: str) -> None:
    """A repeated (key, nonce) pair is the one way AES-GCM fails
    catastrophically: it leaks the XOR of the two plaintexts and the
    authentication key. Storing the same value twice must produce different
    ciphertext every time."""
    v = Vault(encryption_key=Vault.generate_key(), db_path=db)
    blobs = {v.store_secret(f"k{i}", value).encrypted_value for i in range(8)}
    assert len(blobs) == 8, (
        "two encryptions of the same plaintext produced identical ciphertext, "
        "which means the nonce repeated"
    )


# ── Scope is enforced on the read path, not just the write path ──────

def test_a_session_without_the_scope_cannot_read(db) -> None:
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    vault.store_secret("admin_key", "s3cret", scope_required="admin", tenant_id="t")

    weak = gate.create_session("weak", scopes=["read"], ttl=3600, tenant_id="t")
    with pytest.raises(PermissionError):
        vault.get_secret("admin_key", session=weak, tenant_id="t")


def test_a_session_with_the_scope_can_read(db) -> None:
    """The other direction, so the guard cannot be satisfied by refusing
    everything."""
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    vault.store_secret("admin_key", "s3cret", scope_required="admin", tenant_id="t")

    strong = gate.create_session("strong", scopes=["admin"], ttl=3600, tenant_id="t")
    assert vault.get_secret("admin_key", session=strong, tenant_id="t") == "s3cret"


def test_an_expired_session_cannot_read_a_secret(db) -> None:
    """A session that was valid when it was issued must stop working when it
    expires, without anyone having to revoke it."""
    import time as _t

    vault, gate = Vault(db_path=db), Gate(db_path=db)
    vault.store_secret("k", "v", tenant_id="t")
    session = gate.create_session("exp", scopes=["read"], ttl=3600, tenant_id="t")
    session.expires_at = _t.time() - 1

    with pytest.raises(PermissionError):
        vault.get_secret("k", session=session, tenant_id="t")


# ── Rotation preserves every one of those bindings ───────────────────

@given(name=names, tenant=tenants, value=values)
@_SETTINGS
def test_rotation_preserves_both_readability_and_the_bindings(
    db, name: str, tenant: str, value: str
) -> None:
    """Re-keying must not quietly loosen anything. A rotation that dropped
    the AAD binding would leave every secret readable — and every secret
    movable between tenants.

    Runs on values including empty-ish and Unicode ones, because the AAD is
    rebuilt from the tenant and name during rotation and a re-encoding that
    is not byte-identical to the original would fail authentication.
    """
    old_key, new_key = Vault.generate_key(), Vault.generate_key()
    v = Vault(encryption_key=old_key, db_path=db)
    v.store_secret(name, value, tenant_id=tenant)

    v.rotate_keys(new_key)

    fresh = Vault(encryption_key=new_key, db_path=db)
    assert fresh.get_secret(name, tenant_id=tenant) == value

    # And the binding still binds.
    conn = get_db(db)
    blob = bytes(conn.execute("SELECT encrypted_value FROM secrets WHERE name = ?",
                              (name,)).fetchone()["encrypted_value"])
    conn.close()
    fresh._secrets[f"{tenant}-other:{name}"] = SecretEntry(
        name=name, encrypted_value=blob, tenant_id=f"{tenant}-other")
    with pytest.raises((InvalidTag, ValueError)):
        fresh.get_secret(name, tenant_id=f"{tenant}-other")


def test_rotation_does_not_leave_the_old_key_working(db) -> None:
    """After a rotation and once the old key is dropped, it must be useless —
    otherwise "we rotated the key" would not mean anything."""
    old_key, new_key = Vault.generate_key(), Vault.generate_key()
    v = Vault(encryption_key=old_key, db_path=db)
    v.store_secret("k", "v", tenant_id="t")
    v.rotate_keys(new_key)

    as_old = Vault(encryption_key=old_key, db_path=db)
    with pytest.raises((InvalidTag, ValueError)):
        as_old.get_secret("k", tenant_id="t")


def test_a_tenant_cannot_read_another_tenants_secret_by_name(db) -> None:
    """Two tenants using the same secret name is normal — `stripe_key` — and
    must not be a way to read across the boundary."""
    vault = Vault(encryption_key=Vault.generate_key(), db_path=db)
    vault.store_secret("stripe_key", "tenant-one", tenant_id="one")
    vault.store_secret("stripe_key", "tenant-two", tenant_id="two")

    assert vault.get_secret("stripe_key", tenant_id="one") == "tenant-one"
    assert vault.get_secret("stripe_key", tenant_id="two") == "tenant-two"
    assert vault.get_secret("stripe_key", tenant_id="three") is None
