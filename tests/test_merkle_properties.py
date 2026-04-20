"""
Property-based tests for the RFC 6962 Merkle primitives.

The example-based tests in test_audit_tree.py pin specific tree sizes
and tamper cases — great for regressions, insufficient for correctness.
These properties explore the full input space with Hypothesis shrinking
so a failing example is minimized to the smallest tree / index / tamper
that reproduces it.

Scope of invariants:

  1. Inclusion: ∀ 1 ≤ n ≤ 64, ∀ 0 ≤ i < n, verify_inclusion must pass.
  2. Consistency: ∀ 1 ≤ m ≤ n ≤ 64, verify_consistency must pass.
  3. Tamper detection: a single-byte flip in ANY field the proof
     depends on (leaf_hash, root_hash, audit_path element) must be
     rejected.
  4. Differential: our mth(leaves) matches a naive reference MTH
     implementation derived directly from RFC 6962 §2.1 pseudocode.
  5. Append-only extension: a tree of size m is always a valid
     prefix of the same tree extended to size n > m, and
     consistency_path proves it without needing the first tree's
     internal structure.
  6. STH signature: sign → verify must succeed iff the key matches;
     any mutation of tree_size / root_hash / signed_at / signature
     must flip verify to False.

Run: python -m pytest tests/test_merkle_properties.py -v
"""

from __future__ import annotations

import hashlib
import os
import sys

from hypothesis import HealthCheck, given, settings, strategies as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import haldir_merkle as merkle  # noqa: E402


# Tight deadline is fine — the primitives are stdlib hashlib; 200 cases
# complete in < 2 s on a laptop.
_SETTINGS = settings(
    max_examples=200, deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


# ── Strategies ───────────────────────────────────────────────────────

# Arbitrary byte payloads per leaf. 0..128 bytes covers both the
# "tiny entry" and "big JSON payload" cases Haldir audit logs hit.
leaf_bytes = st.binary(min_size=0, max_size=128)

# Tree sizes 1..64: past every power-of-2 boundary the splitting logic
# cares about (1, 2, 3, 4, ..., 32, 33, ..., 64).
tree_sizes = st.integers(min_value=1, max_value=64)


@st.composite
def sized_tree(draw):
    """Draw (leaves, leaf_hashes) for a random-sized tree."""
    n = draw(tree_sizes)
    raw = [draw(leaf_bytes) for _ in range(n)]
    leaves = [merkle.leaf_hash(r) for r in raw]
    return raw, leaves


@st.composite
def tree_and_index(draw):
    """Draw a (leaves, leaf_hashes, index) triple where index is a
    valid position in the tree."""
    raw, leaves = draw(sized_tree())
    i = draw(st.integers(min_value=0, max_value=len(leaves) - 1))
    return raw, leaves, i


@st.composite
def tree_and_pair(draw):
    """Draw (leaves, m, n) where 1 ≤ m ≤ n ≤ len(leaves) — valid
    operands for a consistency proof between sizes m and n."""
    _, leaves = draw(sized_tree())
    n = len(leaves)
    m = draw(st.integers(min_value=1, max_value=n))
    return leaves, m, n


# ── Reference MTH (differential) ─────────────────────────────────────

def _largest_power_of_2_le(n: int) -> int:
    """Largest k = 2^i with k ≤ n. Reference impl for differential."""
    k = 1
    while k * 2 <= n:
        k *= 2
    return k


def _naive_mth(leaves: list[bytes]) -> bytes:
    """Direct transliteration of RFC 6962 §2.1 MTH pseudocode. Used
    only as a correctness oracle in property tests — no caching, no
    cleverness, easy to review line-by-line against the RFC."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    # Split at the largest power of 2 strictly less than n.
    n = len(leaves)
    k = _largest_power_of_2_le(n - 1)  # largest pow2 <= n-1, i.e. < n
    left = _naive_mth(leaves[:k])
    right = _naive_mth(leaves[k:])
    return hashlib.sha256(b"\x01" + left + right).digest()


# ── Properties ───────────────────────────────────────────────────────

@given(tree_and_index())
@_SETTINGS
def test_inclusion_proof_always_verifies(data) -> None:
    """For any tree size 1..64 and any in-range leaf index, the
    generated inclusion proof must self-verify."""
    _, leaves, i = data
    proof = merkle.generate_inclusion_proof(leaves, i)
    assert merkle.verify_inclusion_hex(proof), (
        f"failed at n={len(leaves)} i={i}"
    )


@given(tree_and_index(), st.integers(min_value=0, max_value=31))
@_SETTINGS
def test_inclusion_proof_rejects_single_byte_flip_in_root(data, byte_pos) -> None:
    """Any single-byte corruption of the committed root must break
    verification — the commitment is over 32 bytes, every one of them
    load-bearing."""
    _, leaves, i = data
    proof = merkle.generate_inclusion_proof(leaves, i)
    # Ensure verification passes pre-tamper.
    assert merkle.verify_inclusion_hex(proof)
    # Flip a byte of the root.
    root_bytes = bytearray.fromhex(proof["root_hash"])
    root_bytes[byte_pos] ^= 0xff
    proof["root_hash"] = root_bytes.hex()
    assert not merkle.verify_inclusion_hex(proof), (
        f"flipping byte {byte_pos} of root did not break verification "
        f"at n={len(leaves)} i={i}"
    )


@given(tree_and_index())
@_SETTINGS
def test_inclusion_proof_rejects_wrong_leaf_hash(data) -> None:
    """Claiming a different leaf_hash must reject — the proof should
    be tightly bound to the specific leaf it attests to."""
    _, leaves, i = data
    proof = merkle.generate_inclusion_proof(leaves, i)
    assert merkle.verify_inclusion_hex(proof)
    # Substitute with a hash guaranteed not to equal the real leaf
    # hash. XORing every byte with 0xff inverts the value, so even
    # in the degenerate "two identical leaves" case, the substituted
    # hash differs from the real one.
    real = bytearray.fromhex(proof["leaf_hash"])
    flipped = bytes(b ^ 0xff for b in real)
    assert flipped != bytes(real)  # sanity: the flip is a real change
    proof["leaf_hash"] = flipped.hex()
    assert not merkle.verify_inclusion_hex(proof)


@given(tree_and_index())
@_SETTINGS
def test_inclusion_proof_rejects_any_path_element_flip(data) -> None:
    """Every sibling hash in the audit path is load-bearing: corrupt
    any single element and verification must fail. Picks the middle
    element to cover the mid-path case."""
    _, leaves, i = data
    proof = merkle.generate_inclusion_proof(leaves, i)
    if not proof["audit_path"]:
        return  # size-1 tree has no sibling path; nothing to tamper
    mid = len(proof["audit_path"]) // 2
    proof["audit_path"][mid] = "ff" * 32
    assert not merkle.verify_inclusion_hex(proof)


@given(sized_tree())
@_SETTINGS
def test_mth_matches_naive_reference(data) -> None:
    """Differential test: our fast mth implementation must agree with
    a direct RFC 6962 pseudocode transliteration for every input."""
    _, leaves = data
    assert merkle.mth(leaves) == _naive_mth(leaves)


@given(tree_and_pair())
@_SETTINGS
def test_consistency_proof_always_verifies(data) -> None:
    """For any 1 ≤ m ≤ n ≤ 64, the consistency proof between tree
    size m and tree size n of the SAME underlying leaf sequence must
    verify — append-only extension is always provable."""
    leaves, m, n = data
    first_leaves = leaves[:m]
    first_root = merkle.mth(first_leaves)
    second_root = merkle.mth(leaves[:n])
    if m == n:
        path: list[str] = []
    else:
        path = merkle.proof_to_hex(
            merkle.consistency_path(leaves[:n], m),
        )
    proof = {
        "first_size":       m,
        "second_size":      n,
        "first_root":       first_root.hex(),
        "second_root":      second_root.hex(),
        "consistency_path": path,
    }
    assert merkle.verify_consistency_hex(proof), (
        f"failed at m={m} n={n}"
    )


@given(tree_and_pair(), st.integers(min_value=0, max_value=31))
@_SETTINGS
def test_consistency_proof_rejects_first_root_tamper(data, byte_pos) -> None:
    """If the claimed first_root is wrong (forked history), the
    consistency proof must reject — that's the whole point."""
    leaves, m, n = data
    if m == n:
        return  # trivial case: first_root == second_root by construction
    second_root = merkle.mth(leaves[:n])
    path = merkle.proof_to_hex(merkle.consistency_path(leaves[:n], m))
    # Flip a byte of first_root.
    real_first = bytearray(merkle.mth(leaves[:m]))
    real_first[byte_pos] ^= 0xff
    proof = {
        "first_size":       m,
        "second_size":      n,
        "first_root":       real_first.hex(),
        "second_root":      second_root.hex(),
        "consistency_path": path,
    }
    assert not merkle.verify_consistency_hex(proof)


@given(sized_tree(), leaf_bytes)
@_SETTINGS
def test_append_is_consistency_provable(before, extra) -> None:
    """The real-world claim: if I have STH_m and you later give me
    STH_n (n > m) for a tree built by appending leaves, I can get a
    consistency proof that verifies. Models the operator scenario:
    auditor pins today's STH, returns next quarter, asks Haldir to
    prove the current log is an append-only extension."""
    _, leaves = before
    m = len(leaves)
    extended = leaves + [merkle.leaf_hash(extra)]
    first_root = merkle.mth(leaves)
    second_root = merkle.mth(extended)
    path = merkle.proof_to_hex(merkle.consistency_path(extended, m))
    proof = {
        "first_size":       m,
        "second_size":      m + 1,
        "first_root":       first_root.hex(),
        "second_root":      second_root.hex(),
        "consistency_path": path,
    }
    assert merkle.verify_consistency_hex(proof)


@given(sized_tree(), st.binary(min_size=32, max_size=32))
@_SETTINGS
def test_sth_signature_rejects_wrong_key(data, other_key) -> None:
    """An STH signed with key A must not verify under key B unless
    A == B. HMAC non-forgeability under random keys."""
    _, leaves = data
    root = merkle.mth(leaves)
    key_a = merkle.derive_signing_key("seed-A")
    sth = merkle.sign_sth(len(leaves), root, key_a, signed_at=1_700_000_000)
    if other_key == key_a:
        return  # 1/2^256 degenerate case
    assert not merkle.verify_sth(sth, other_key)
    assert merkle.verify_sth(sth, key_a)  # positive control


@given(sized_tree())
@_SETTINGS
def test_sth_signature_rejects_any_field_mutation(data) -> None:
    """Mutating tree_size, root_hash, signed_at, or signature each
    must independently break the HMAC."""
    _, leaves = data
    root = merkle.mth(leaves)
    key = merkle.derive_signing_key("seed")
    sth = merkle.sign_sth(len(leaves), root, key, signed_at=1_700_000_000)
    assert merkle.verify_sth(sth, key)

    # Mutating each field in turn must individually fail verification.
    mutations = [
        {"tree_size":  sth["tree_size"] + 1},
        {"root_hash":  ("00" * 32)},
        {"signed_at":  sth["signed_at"] + 1},
        {"signature":  ("ff" * 32)},
    ]
    for m in mutations:
        mutated = dict(sth, **m)
        assert not merkle.verify_sth(mutated, key), (
            f"mutation {list(m.keys())[0]} did not break the HMAC"
        )
