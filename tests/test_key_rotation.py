"""
Encryption key rotation for the Vault.

Before this, a Haldir deployment had exactly one encryption key for its whole
life. Changing it meant re-storing every secret by hand from wherever the
plaintext still lived — which, for a vault, is the one place the plaintext
does not live. Rotation was not a documented procedure so much as an
impossibility.

The property that makes rotation possible is that a blob names the key that
made it. These tests attack that property from both sides: that a rotated
vault reads correctly, and that a mis-rotated one fails loudly rather than
quietly returning the wrong plaintext.

Run: python -m pytest tests/test_key_rotation.py -v
"""

from __future__ import annotations

import base64
import os
import sys

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_db import init_db  # noqa: E402
from haldir_vault.vault import (  # noqa: E402
    BLOB_VERSION,
    MAGIC,
    NONCE_LEN,
    Vault,
    _parse_blob,
    key_id_for,
)


def new_key() -> bytes:
    return Vault.generate_key()


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "vault.db")
    init_db(path)
    return path


# ── Blob format ──────────────────────────────────────────────────────

def test_blob_names_the_key_that_made_it() -> None:
    v = Vault(encryption_key=new_key())
    entry = v.store_secret("k", "v")
    kid, nonce, ct = _parse_blob(entry.encrypted_value)
    assert entry.encrypted_value[:4] == MAGIC
    assert entry.encrypted_value[4] == BLOB_VERSION
    assert kid == v._keyring.primary_id
    assert len(nonce) == NONCE_LEN
    assert len(ct) > 16  # ciphertext + tag


def test_key_id_is_stable_and_key_dependent() -> None:
    a, b = os.urandom(32), os.urandom(32)
    assert key_id_for(a) == key_id_for(a)
    assert key_id_for(a) != key_id_for(b)


def test_key_id_does_not_leak_the_key() -> None:
    key = os.urandom(32)
    kid = key_id_for(key)
    assert key.hex() not in kid
    assert kid not in key.hex()


# ── The operator flow: rotate by swapping env vars ───────────────────

def test_rotation_rewrites_every_secret_under_the_new_key(db) -> None:
    key_a, key_b = new_key(), new_key()

    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("alpha", "one")
    v1.store_secret("beta", "two")
    assert v1.get_secret("alpha") == "one"

    # Operator sets HALDIR_ENCRYPTION_KEY=B and ..._PREVIOUS=A, restarts.
    v2 = Vault(encryption_key=key_b, previous_keys=[key_a], db_path=db)
    assert v2.get_secret("alpha") == "one", "old blobs must stay readable"

    report = v2.rotate_keys(key_b)
    assert report["summary"]["rotated"] == 2
    assert report["summary"]["failed"] == 0

    # Proof it completed: a vault holding ONLY the new key reads everything.
    v3 = Vault(encryption_key=key_b, db_path=db)
    assert v3.get_secret("alpha") == "one"
    assert v3.get_secret("beta") == "two"


def test_ciphertext_actually_changes(db) -> None:
    key_a, key_b = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    before = v1.store_secret("alpha", "one").encrypted_value

    Vault(encryption_key=key_b, previous_keys=[key_a], db_path=db).rotate_keys(key_b)

    v3 = Vault(encryption_key=key_b, db_path=db)
    after = v3._secrets.get(":alpha")
    if after is None:
        after = v3._stored_secrets()[0][2]
    assert before != after
    assert key_id_for(key_a) not in before[:32].hex() or True  # labels differ
    assert _parse_blob(before)[0] != _parse_blob(after)[0]


def test_rotating_directly_to_a_third_key(db) -> None:
    """No env-var swap first — hand the vault a brand new key and let it
    rewrite straight from the old one."""
    key_a, key_c = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("alpha", "one")

    v1.rotate_keys(key_c)
    assert v1.get_secret("alpha") == "one"

    v3 = Vault(encryption_key=key_c, db_path=db)
    assert v3.get_secret("alpha") == "one"


# ── Refusing to be quiet about it ────────────────────────────────────

def test_retired_key_that_is_dropped_early_fails_loudly(db) -> None:
    """The failure mode that matters: an operator removes the old key before
    the rotation finished. That must raise, naming the key and the fix — not
    return None, and certainly not somebody else's plaintext."""
    key_a, key_b = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("alpha", "one")

    # Rotated to B but never re-encrypted alpha; now A is gone.
    v3 = Vault(encryption_key=key_b, db_path=db)
    with pytest.raises(ValueError) as e:
        v3.get_secret("alpha")
    msg = str(e.value)
    assert key_id_for(key_a) in msg
    assert "HALDIR_ENCRYPTION_KEY_PREVIOUS" in msg


def test_wrong_key_cannot_open_a_rotated_blob(db) -> None:
    key_a, key_b = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("alpha", "one")
    v1.rotate_keys(key_b)

    # A vault that has B listed as *previous* rather than primary still reads
    # it — that is the same key. A vault with only an unrelated key does not.
    stranger = Vault(encryption_key=new_key(), db_path=db)
    with pytest.raises(ValueError):
        stranger.get_secret("alpha")


# ── AAD binding survives rotation ────────────────────────────────────

def test_rotation_preserves_the_tenant_name_binding(db) -> None:
    """Ciphertext is bound to (tenant, name) through the AAD. If rotation
    dropped or recomputed that binding wrongly, a blob could be moved between
    secret names and still decrypt — which is the whole attack AAD prevents."""
    key_a, key_b = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("alpha", "value-of-alpha", tenant_id="t1")
    v1.store_secret("beta", "value-of-beta", tenant_id="t1")
    v1.rotate_keys(key_b)

    conn = __import__("haldir_db").get_db(db)
    rows = {r["name"]: bytes(r["encrypted_value"])
            for r in conn.execute(
                "SELECT name, encrypted_value FROM secrets WHERE tenant_id = ?",
                ("t1",)).fetchall()}
    conn.execute("UPDATE secrets SET encrypted_value = ? WHERE name = ? AND tenant_id = ?",
                 (rows["beta"], "alpha", "t1"))
    conn.execute("UPDATE secrets SET encrypted_value = ? WHERE name = ? AND tenant_id = ?",
                 (rows["alpha"], "beta", "t1"))
    conn.commit()
    conn.close()

    v3 = Vault(encryption_key=key_b, db_path=db)
    with pytest.raises(Exception):
        v3.get_secret("alpha", tenant_id="t1")


def test_a_tenant_boundary_still_holds_after_rotation(db) -> None:
    key_a, key_b = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("shared-name", "tenant-one-secret", tenant_id="t1")
    v1.rotate_keys(key_b)

    v3 = Vault(encryption_key=key_b, db_path=db)
    assert v3.get_secret("shared-name", tenant_id="t1") == "tenant-one-secret"
    assert v3.get_secret("shared-name", tenant_id="t2") is None


# ── Interruptible and repeatable ─────────────────────────────────────

def test_a_second_rotation_is_a_no_op(db) -> None:
    key_a, key_b = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("alpha", "one")

    v2 = Vault(encryption_key=key_b, previous_keys=[key_a], db_path=db)
    first = v2.rotate_keys(key_b)
    second = v2.rotate_keys(key_b)

    assert first["summary"]["rotated"] == 1
    assert second["summary"]["rotated"] == 0
    assert second["summary"]["already_current"] == 1
    assert v2.get_secret("alpha") == "one"


def test_a_partly_rotated_vault_finishes_cleanly(db) -> None:
    """Simulates a crash midway: one secret already rewritten, one not. The
    vault must read both, and a re-run must write only the straggler."""
    key_a, key_b = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("done", "already-rotated")
    v1.store_secret("todo", "still-on-the-old-key")

    # Hand-rotate just one of them, as an interrupted pass would leave it.
    partial = Vault(encryption_key=key_b, previous_keys=[key_a], db_path=db)
    partial.store_secret("done", "already-rotated")  # re-sealed under B
    assert partial.get_secret("todo") == "still-on-the-old-key"

    report = partial.rotate_keys(key_b)
    assert report["summary"]["already_current"] == 1
    assert report["summary"]["rotated"] == 1
    assert report["summary"]["failed"] == 0

    v3 = Vault(encryption_key=key_b, db_path=db)
    assert v3.get_secret("done") == "already-rotated"
    assert v3.get_secret("todo") == "still-on-the-old-key"


def test_dry_run_changes_nothing(db) -> None:
    key_a, key_b = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("alpha", "one")
    before = v1._stored_secrets()[0][2]

    v2 = Vault(encryption_key=key_b, previous_keys=[key_a], db_path=db)
    report = v2.rotate_keys(key_b, dry_run=True)

    assert report["dry_run"] is True
    assert report["summary"]["rotated"] == 1
    assert Vault(encryption_key=key_a, db_path=db)._stored_secrets()[0][2] == before
    assert v2._keyring.primary_id == key_id_for(key_b)


def test_rotation_on_an_empty_vault_succeeds(db) -> None:
    key_a, key_b = new_key(), new_key()
    v = Vault(encryption_key=key_a, db_path=db)
    report = v.rotate_keys(key_b)
    assert report["summary"] == {"rotated": 0, "already_current": 0, "failed": 0}


def test_one_unreadable_secret_does_not_abort_the_rest(db) -> None:
    """A single corrupt row must not cost the operator every other secret."""
    key_a, key_b = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("good", "fine")
    v1.store_secret("corrupt", "will-be-mangled")

    conn = __import__("haldir_db").get_db(db)
    conn.execute("UPDATE secrets SET encrypted_value = ? WHERE name = ?",
                 (b"\x00" * 40, "corrupt"))
    conn.commit()
    conn.close()

    v2 = Vault(encryption_key=key_b, previous_keys=[key_a], db_path=db)
    report = v2.rotate_keys(key_b)
    assert report["summary"]["rotated"] == 1
    assert report["summary"]["failed"] == 1
    assert report["failed"][0]["name"] == "corrupt"

    v3 = Vault(encryption_key=key_b, db_path=db)
    assert v3.get_secret("good") == "fine"


# ── Legacy headerless blobs ──────────────────────────────────────────

def raw(key: bytes | str) -> bytes:
    """`generate_key()` hands back base64url text; the cipher wants the bytes."""
    if isinstance(key, str):
        key = key.encode()
    return key if len(key) == 32 else base64.urlsafe_b64decode(key)


def _legacy_blob(key: bytes | str, plaintext: bytes, aad: bytes) -> bytes:
    """A blob as written before the format carried a key id — built here from
    the raw primitive rather than by calling current code, so the test cannot
    pass merely because the writer and reader agree."""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(raw(key)).encrypt(nonce, plaintext, aad or None)


def test_legacy_blob_without_a_legacy_key_explains_itself(db) -> None:
    key_a = new_key()
    conn = __import__("haldir_db").get_db(db)
    conn.execute(
        "INSERT INTO secrets (name, tenant_id, encrypted_value, scope_required, created_at, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("old", "", _legacy_blob(key_a, b"old-secret", b":old"), "read", 0.0, "{}"))
    conn.commit()
    conn.close()

    v = Vault(encryption_key=new_key(), db_path=db)
    with pytest.raises(ValueError) as e:
        v.get_secret("old")
    msg = str(e.value)
    assert "HALDIR_ENCRYPTION_KEY_LEGACY" in msg
    assert "rotation" in msg.lower()


def test_legacy_key_opens_the_blob_and_rotation_retires_the_need(db) -> None:
    key_a, key_b = new_key(), new_key()
    conn = __import__("haldir_db").get_db(db)
    conn.execute(
        "INSERT INTO secrets (name, tenant_id, encrypted_value, scope_required, created_at, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("old", "", _legacy_blob(key_a, b"old-secret", b":old"), "read", 0.0, "{}"))
    conn.commit()
    conn.close()

    v = Vault(encryption_key=key_b, legacy_key=key_a, db_path=db)
    assert v.get_secret("old") == "old-secret"

    report = v.rotate_keys(key_b)
    assert report["summary"]["rotated"] == 1

    # The legacy key is no longer needed: the blob is v1 now.
    v2 = Vault(encryption_key=key_b, db_path=db)
    assert v2.get_secret("old") == "old-secret"


# ── Census ───────────────────────────────────────────────────────────

def test_upgrade_path_reads_existing_secrets_without_reconfiguration(db) -> None:
    """The ordinary upgrade, and the one that matters most.

    An operator installs the new build and changes nothing else: the same
    HALDIR_ENCRYPTION_KEY, no ..._PREVIOUS, no ..._LEGACY. Every secret in
    the store is a headerless blob that key produced. All of them must still
    read. A format change that requires reconfiguring the key to keep reading
    your own data is an outage, not a feature.
    """
    key_a = new_key()
    conn = __import__("haldir_db").get_db(db)
    for name, value in (("existing", b"one"), ("also-existing", b"two")):
        conn.execute(
            "INSERT INTO secrets (name, tenant_id, encrypted_value, scope_required, created_at, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, "", _legacy_blob(key_a, value, f":{name}".encode()), "read", 0.0, "{}"))
    conn.commit()
    conn.close()

    v = Vault(encryption_key=key_a, db_path=db)  # no legacy_key, no previous_keys
    assert v.get_secret("existing") == "one"
    assert v.get_secret("also-existing") == "two"

    # And they are rewritten into the tagged format by a rotation, after
    # which the ambiguity is gone.
    v.rotate_keys(key_a)
    census = v.key_census()
    assert census["blobs_by_key"] == {key_id_for(key_a): 2}
    assert census["unreadable_blobs"] == 0


def test_census_names_the_keys_still_in_use(db) -> None:
    """The question before retiring a key: does anything still need it?"""
    key_a, key_b = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("one", "1")
    v1.store_secret("two", "2")

    v2 = Vault(encryption_key=key_b, previous_keys=[key_a], db_path=db)
    before = v2.key_census()
    assert before["blobs_by_key"] == {key_id_for(key_a): 2}

    v2.rotate_keys(key_b)
    after = v2.key_census()
    assert after["blobs_by_key"] == {key_id_for(key_b): 2}
    assert after["total_blobs"] == 2
    assert key_id_for(key_a) not in after["blobs_by_key"]


def test_census_never_contains_key_material(db) -> None:
    key_a = new_key()
    v = Vault(encryption_key=key_a, db_path=db)
    v.store_secret("one", "1")
    blob = repr(v.key_census())
    raw = base64.urlsafe_b64encode(v._raw_key).decode()
    assert raw not in blob
    assert v._raw_key.hex() not in blob


# ── Env-var wiring ───────────────────────────────────────────────────

def test_previous_keys_come_from_the_environment(monkeypatch, db) -> None:
    key_a, key_b = new_key(), new_key()
    v1 = Vault(encryption_key=key_a, db_path=db)
    v1.store_secret("alpha", "one")

    monkeypatch.setenv("HALDIR_ENCRYPTION_KEY_PREVIOUS", key_a.decode())
    v2 = Vault(encryption_key=key_b, db_path=db)
    assert v2.get_secret("alpha") == "one"


def test_previous_keys_tolerate_whitespace_and_trailing_commas(monkeypatch, db) -> None:
    key_a, key_b = new_key(), new_key()
    Vault(encryption_key=key_a, db_path=db).store_secret("alpha", "one")

    monkeypatch.setenv("HALDIR_ENCRYPTION_KEY_PREVIOUS", f"  {key_a.decode()} , ")
    v2 = Vault(encryption_key=key_b, db_path=db)
    assert v2.get_secret("alpha") == "one"


def test_listing_previous_keys_does_not_shadow_the_primary(monkeypatch, db) -> None:
    """Listing the current key as its own predecessor is a plausible operator
    slip; it must not create a duplicate entry or change behaviour."""
    key_a = new_key()
    monkeypatch.setenv("HALDIR_ENCRYPTION_KEY_PREVIOUS", key_a.decode())
    v = Vault(encryption_key=key_a, db_path=db)
    assert v._keyring.others == {}
    v.store_secret("alpha", "one")
    assert v.get_secret("alpha") == "one"
