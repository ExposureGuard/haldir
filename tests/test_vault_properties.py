"""
Property-based tests for the Vault using Hypothesis.

These don't replace `tests/test_vault.py` — they complement it. Unit tests
prove specific cases work; property tests prove invariants hold across the
whole input space, finding edge cases (empty strings, weird unicode,
boundary-length plaintexts, payload sizes near GCM limits) that hand-
written cases miss.

Run: python -m pytest tests/test_vault_properties.py -v
"""

from __future__ import annotations

import base64
import os
import sys

import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import HealthCheck, given, settings, strategies as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_vault import Vault
from haldir_vault.vault import KEY_LEN, SecretEntry


# Slightly relaxed settings — the Vault touches an in-memory dict so generation
# is fast, but we cap examples to keep CI quick.
_SETTINGS = settings(max_examples=200, deadline=None,
                     suppress_health_check=[HealthCheck.too_slow])


# ── Strategies ───────────────────────────────────────────────────────────

# Plaintexts: any UTF-8 string up to 4 KiB. Vault has no documented size cap
# (the API does, separately), so the crypto layer must round-trip arbitrary
# UTF-8 of arbitrary length.
plaintexts = st.text(min_size=0, max_size=4096)

# Identifiers used as AAD: tenant_id and secret_name. These can contain
# colons in real usage (the AAD is "tenant:name"), so we deliberately
# include `:` in the alphabet to stress AAD parsing assumptions.
identifiers = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126),
    min_size=1, max_size=64,
)

# Raw 32-byte keys
raw_keys = st.binary(min_size=KEY_LEN, max_size=KEY_LEN)


# ── Properties ───────────────────────────────────────────────────────────

@_SETTINGS
@given(plaintext=plaintexts, name=identifiers, tenant=identifiers)
def test_roundtrip_for_any_utf8_plaintext(plaintext: str, name: str, tenant: str) -> None:
    """For ANY plaintext + (tenant, name) tuple, encrypt-then-decrypt is identity."""
    v = Vault(encryption_key=Vault.generate_key())
    v.store_secret(name=name, value=plaintext, tenant_id=tenant)
    assert v.get_secret(name=name, tenant_id=tenant) == plaintext


@_SETTINGS
@given(plaintext=plaintexts, name=identifiers, tenant=identifiers)
def test_two_stores_of_same_value_yield_distinct_ciphertexts(
    plaintext: str, name: str, tenant: str
) -> None:
    """Fresh nonce per encryption: same plaintext + AAD should not produce
    identical ciphertext (probabilistic — collision space is 2**96)."""
    v = Vault(encryption_key=Vault.generate_key())
    e1 = v.store_secret(name=name, value=plaintext, tenant_id=tenant)
    # Re-store under a different name to avoid the in-memory dict overwriting
    e2 = v.store_secret(name=name + "_2", value=plaintext, tenant_id=tenant)
    assert e1.encrypted_value != e2.encrypted_value


@_SETTINGS
@given(
    plaintext=plaintexts,
    name=identifiers,
    tenant_a=identifiers,
    tenant_b=identifiers,
)
def test_cross_tenant_swap_always_fails(
    plaintext: str, name: str, tenant_a: str, tenant_b: str
) -> None:
    """For any (plaintext, name, A, B) with A != B, ciphertext encrypted under
    tenant A cannot be decrypted as tenant B's. AEAD AAD binding."""
    if tenant_a == tenant_b:
        return  # same tenant — not a swap

    v = Vault(encryption_key=Vault.generate_key())
    e_a = v.store_secret(name=name, value=plaintext, tenant_id=tenant_a)

    # Inject the ciphertext under tenant B; decryption should fail
    v._secrets[f"{tenant_b}:{name}"] = SecretEntry(
        name=name,
        encrypted_value=e_a.encrypted_value,
        tenant_id=tenant_b,
    )
    with pytest.raises(InvalidTag):
        v.get_secret(name=name, tenant_id=tenant_b)


@_SETTINGS
@given(
    plaintext=plaintexts,
    tenant=identifiers,
    name_a=identifiers,
    name_b=identifiers,
)
def test_cross_name_swap_always_fails(
    plaintext: str, tenant: str, name_a: str, name_b: str
) -> None:
    """Similar to cross-tenant: ciphertext stored as name A cannot be renamed
    to name B and decrypt successfully."""
    if name_a == name_b:
        return

    v = Vault(encryption_key=Vault.generate_key())
    e_a = v.store_secret(name=name_a, value=plaintext, tenant_id=tenant)

    v._secrets[f"{tenant}:{name_b}"] = SecretEntry(
        name=name_b,
        encrypted_value=e_a.encrypted_value,
        tenant_id=tenant,
    )
    with pytest.raises(InvalidTag):
        v.get_secret(name=name_b, tenant_id=tenant)


@_SETTINGS
@given(plaintext=plaintexts, key_a=raw_keys, key_b=raw_keys, name=identifiers)
def test_decryption_under_different_key_always_fails(
    plaintext: str, key_a: bytes, key_b: bytes, name: str
) -> None:
    """For any plaintext and any pair of distinct keys, swapping keys breaks
    decryption deterministically."""
    if key_a == key_b:
        return

    v_a = Vault(encryption_key=key_a)
    e = v_a.store_secret(name=name, value=plaintext, tenant_id="t")

    v_b = Vault(encryption_key=key_b)
    v_b._secrets[f"t:{name}"] = SecretEntry(
        name=name, encrypted_value=e.encrypted_value, tenant_id="t",
    )
    with pytest.raises(InvalidTag):
        v_b.get_secret(name=name, tenant_id="t")


@_SETTINGS
@given(key=raw_keys)
def test_generated_key_property_is_self_consistent(key: bytes) -> None:
    """A Vault built from a raw 32-byte key, when its `encryption_key`
    property is read back and used to construct another Vault, the two
    encrypt/decrypt the same ciphertexts identically."""
    v1 = Vault(encryption_key=key)
    e = v1.store_secret(name="k", value="hello", tenant_id="t")

    # Round-trip the key via the property (which returns base64url form)
    v2 = Vault(encryption_key=v1.encryption_key)
    v2._secrets["t:k"] = SecretEntry(name="k", encrypted_value=e.encrypted_value, tenant_id="t")
    assert v2.get_secret(name="k", tenant_id="t") == "hello"


@_SETTINGS
@given(key_bytes=st.binary(min_size=1, max_size=KEY_LEN - 1))
def test_short_keys_are_rejected(key_bytes: bytes) -> None:
    """A non-empty short key should raise — except for the narrow case
    where the base64 encoding happens to be exactly 32 chars long (e.g. 22
    bytes of zeros), which the current `_decode_key` heuristic treats as a
    raw 32-byte key. See known-edge-case note in the Vault docstring; a
    smarter heuristic is on the roadmap."""
    encoded = base64.urlsafe_b64encode(key_bytes)
    if len(encoded) == KEY_LEN:
        return  # ambiguous-length input; skip
    with pytest.raises(ValueError):
        Vault(encryption_key=encoded)
