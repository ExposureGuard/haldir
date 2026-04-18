"""
Tests for haldir_vault.vault.Vault (AES-256-GCM).

Covers:
  - Roundtrip correctness
  - AEAD additional authenticated data binding:
      * cross-tenant ciphertext swap rejection
      * cross-name ciphertext swap rejection
  - Wrong-key rejection
  - Both supported key formats (raw 32-byte, base64url-encoded)
  - Key generation conforms to length + format invariants

Run: python -m pytest tests/test_vault.py -v
"""

from __future__ import annotations

import base64
import os
import sys

import pytest
from cryptography.exceptions import InvalidTag

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_vault import Vault
from haldir_vault.vault import KEY_LEN, NONCE_LEN, SecretEntry


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def vault() -> Vault:
    """Fresh in-memory Vault with a random 256-bit key."""
    return Vault(encryption_key=Vault.generate_key())


# ── Key generation ───────────────────────────────────────────────────────

def test_generate_key_returns_base64url_of_32_bytes() -> None:
    key = Vault.generate_key()
    assert isinstance(key, bytes)
    decoded = base64.urlsafe_b64decode(key)
    assert len(decoded) == KEY_LEN


def test_generate_key_is_unique_per_call() -> None:
    assert Vault.generate_key() != Vault.generate_key()


# ── Roundtrip ────────────────────────────────────────────────────────────

def test_roundtrip_plaintext_recovered(vault: Vault) -> None:
    plaintext = "sk_live_supersecret_abc123"
    vault.store_secret(name="stripe", value=plaintext, tenant_id="t1")
    assert vault.get_secret(name="stripe", tenant_id="t1") == plaintext


def test_ciphertext_is_at_least_nonce_plus_tag(vault: Vault) -> None:
    entry = vault.store_secret(name="k", value="v", tenant_id="t")
    # 12-byte nonce + 16-byte GCM tag floor
    assert len(entry.encrypted_value) >= NONCE_LEN + 16


def test_store_twice_yields_different_ciphertexts(vault: Vault) -> None:
    """Each encryption uses a fresh random nonce, so ciphertexts should differ."""
    e1 = vault.store_secret(name="k1", value="same-value", tenant_id="t")
    e2 = vault.store_secret(name="k2", value="same-value", tenant_id="t")
    assert e1.encrypted_value != e2.encrypted_value


# ── AAD binding (defense in depth) ───────────────────────────────────────

def test_cross_tenant_ciphertext_swap_rejected(vault: Vault) -> None:
    """An attacker with DB write access cannot move ciphertext between tenants."""
    original = vault.store_secret(name="api_key", value="secret", tenant_id="alice")
    # Simulate DB tampering: inject the ciphertext under bob's tenant
    vault._secrets["bob:api_key"] = SecretEntry(
        name="api_key",
        encrypted_value=original.encrypted_value,
        tenant_id="bob",
    )
    with pytest.raises(InvalidTag):
        vault.get_secret(name="api_key", tenant_id="bob")


def test_cross_name_ciphertext_swap_rejected(vault: Vault) -> None:
    """Ciphertext cannot be renamed within the same tenant."""
    original = vault.store_secret(name="original_name", value="secret", tenant_id="t")
    vault._secrets["t:different_name"] = SecretEntry(
        name="different_name",
        encrypted_value=original.encrypted_value,
        tenant_id="t",
    )
    with pytest.raises(InvalidTag):
        vault.get_secret(name="different_name", tenant_id="t")


# ── Wrong key ────────────────────────────────────────────────────────────

def test_decrypt_with_wrong_key_raises_invalid_tag() -> None:
    v1 = Vault(encryption_key=Vault.generate_key())
    original = v1.store_secret(name="k", value="v", tenant_id="t")

    v2 = Vault(encryption_key=Vault.generate_key())  # different random key
    v2._secrets["t:k"] = SecretEntry(
        name="k",
        encrypted_value=original.encrypted_value,
        tenant_id="t",
    )
    with pytest.raises(InvalidTag):
        v2.get_secret(name="k", tenant_id="t")


# ── Key input formats ────────────────────────────────────────────────────

def test_accepts_raw_32_byte_key() -> None:
    raw = os.urandom(KEY_LEN)
    v = Vault(encryption_key=raw)
    v.store_secret(name="k", value="v", tenant_id="t")
    assert v.get_secret(name="k", tenant_id="t") == "v"


def test_accepts_base64url_encoded_key() -> None:
    b64 = base64.urlsafe_b64encode(os.urandom(KEY_LEN))
    v = Vault(encryption_key=b64)
    v.store_secret(name="k", value="v", tenant_id="t")
    assert v.get_secret(name="k", tenant_id="t") == "v"


def test_accepts_string_form_of_base64_key() -> None:
    """Convenience: accept the base64url key as a str (not just bytes)."""
    b64 = base64.urlsafe_b64encode(os.urandom(KEY_LEN)).decode()
    v = Vault(encryption_key=b64)
    v.store_secret(name="k", value="v", tenant_id="t")
    assert v.get_secret(name="k", tenant_id="t") == "v"


def test_rejects_short_key() -> None:
    short = os.urandom(16)  # AES-128-sized key, not valid for AES-256
    with pytest.raises(ValueError, match="expected 32"):
        Vault(encryption_key=base64.urlsafe_b64encode(short))


def test_rejects_garbage_key() -> None:
    with pytest.raises(ValueError):
        Vault(encryption_key=b"not-a-base64-key-nor-32-raw-bytes-of-entropy!")


# ── Delete + list ────────────────────────────────────────────────────────

def test_delete_removes_secret(vault: Vault) -> None:
    vault.store_secret(name="k", value="v", tenant_id="t")
    assert vault.get_secret(name="k", tenant_id="t") == "v"
    vault.delete_secret(name="k", tenant_id="t")
    assert vault.get_secret(name="k", tenant_id="t") is None


def test_list_returns_names_for_tenant(vault: Vault) -> None:
    vault.store_secret(name="k1", value="v1", tenant_id="alice")
    vault.store_secret(name="k2", value="v2", tenant_id="alice")
    vault.store_secret(name="k3", value="v3", tenant_id="bob")

    assert sorted(vault.list_secrets(tenant_id="alice")) == ["k1", "k2"]
    assert vault.list_secrets(tenant_id="bob") == ["k3"]


# ── Encryption key roundtrip ─────────────────────────────────────────────

def test_encryption_key_property_returns_base64url_form() -> None:
    key = Vault.generate_key()
    v = Vault(encryption_key=key)
    # The returned key should be decodable as base64url of 32 bytes
    returned = v.encryption_key
    assert len(base64.urlsafe_b64decode(returned)) == KEY_LEN


def test_new_vault_with_returned_key_decrypts_existing_ciphertext() -> None:
    """You can persist v.encryption_key and rehydrate a Vault with it."""
    v1 = Vault()  # auto-generates a key
    stored = v1.store_secret(name="k", value="secret", tenant_id="t")

    v2 = Vault(encryption_key=v1.encryption_key)
    v2._secrets["t:k"] = SecretEntry(
        name="k",
        encrypted_value=stored.encrypted_value,
        tenant_id="t",
    )
    assert v2.get_secret(name="k", tenant_id="t") == "secret"
