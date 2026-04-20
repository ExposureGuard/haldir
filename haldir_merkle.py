"""
RFC 6962 Merkle tree primitives for Haldir's audit log.

Why this is the right primitive:

  The hash chain we already ship (SHA-256 of each entry + previous
  entry's hash) makes sequential tampering detectable, but:

    1. Verifying needs the ENTIRE chain — you can't prove "entry X
       was in the log at time T" without showing every entry leading
       up to it.
    2. Two parties holding the same log can't agree on a single
       short digest for "the log as of now."
    3. You can't cheaply prove "nothing was deleted between last
       audit and this audit."

  A Merkle tree solves all three. The log's entire state is reduced
  to one 32-byte root hash; inclusion of a specific entry is proven
  in O(log n) sibling hashes; consistency between two tree states
  is proven in O(log n) hashes — the Certificate Transparency
  primitive, the Sigstore primitive, and the only design a
  cryptography-literate auditor accepts as "tamper-evident" in the
  spec sense.

This module is a strict RFC 6962 implementation + Haldir's Signed
Tree Head format. Stdlib-only (hashlib + hmac + json + time).
Pure-function so the SDK can re-export these same verifiers
unchanged, giving auditors offline verification without trust in
Haldir.

── Conformance ──────────────────────────────────────────────────────

  Leaf hash:       H(0x00 || data)      — RFC 6962 §2.1
  Internal hash:   H(0x01 || left || right)
  Empty tree hash: SHA-256("") = e3b0c442...

  PATH(m, D[n]):   RFC 6962 §2.1.1 — inclusion proof
  PROOF(m, D[n]):  RFC 6962 §2.1.2 — consistency proof

── Signed Tree Head (Haldir-specific) ───────────────────────────────

  Canonical form: f"sth:{tree_size}:{root_hex}:{signed_at}".encode()
  Signature:      HMAC-SHA256 over canonical form with a server-held
                  signing key derived from HALDIR_TREE_SIGNING_KEY
                  (or HALDIR_ENCRYPTION_KEY as fallback, or an
                  ephemeral key in dev — logged warning).

  Auditor verifies an STH by recomputing the HMAC with the same key
  Haldir published in its STH-signing-key endpoint (future: publish
  as JWKS). For v1 the key lives server-side; auditors trust Haldir
  for STH signature but NOT for inclusion proofs (those are
  cryptographically self-verifying given a trusted STH).

"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Iterable


# ── RFC 6962 primitive hashes ─────────────────────────────────────

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || data)."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 internal hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def empty_tree_hash() -> bytes:
    """RFC 6962 §2.1: MTH({}) = SHA-256()."""
    return hashlib.sha256(b"").digest()


def _largest_power_of_2_lt(n: int) -> int:
    """Largest power of 2 strictly less than n. Undefined for n <= 1."""
    if n <= 1:
        raise ValueError("n must be >= 2")
    k = 1
    while k * 2 < n:
        k *= 2
    return k


# ── Merkle Tree Hash ──────────────────────────────────────────────

def mth(leaves: list[bytes]) -> bytes:
    """Merkle Tree Hash per RFC 6962 §2.1.

    `leaves` is the list of *already leaf-hashed* values, i.e. each
    element is the 32-byte output of leaf_hash(entry_bytes). Keeping
    the leaf-hashing separate lets callers reuse an on-disk list of
    entry hashes without re-hashing."""
    n = len(leaves)
    if n == 0:
        return empty_tree_hash()
    if n == 1:
        return leaves[0]
    k = _largest_power_of_2_lt(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


# ── Inclusion proof (RFC 6962 §2.1.1) ─────────────────────────────

def inclusion_path(leaves: list[bytes], index: int) -> list[bytes]:
    """PATH(m, D[n]) per RFC 6962: sibling hashes needed to
    reconstruct the root from leaves[index].

    `leaves` is leaf-hashes (same shape as mth() input). `index` is
    the 0-based position of the target leaf within the current
    tree."""
    n = len(leaves)
    if n <= 0:
        raise ValueError("tree must have at least one leaf")
    if not 0 <= index < n:
        raise ValueError(f"index {index} out of range for size {n}")
    return _inclusion_path_recursive(leaves, index)


def _inclusion_path_recursive(leaves: list[bytes], index: int) -> list[bytes]:
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_power_of_2_lt(n)
    if index < k:
        # target in left subtree → path from left + right subtree hash
        return _inclusion_path_recursive(leaves[:k], index) + [mth(leaves[k:])]
    else:
        # target in right subtree → path from right + left subtree hash
        return (_inclusion_path_recursive(leaves[k:], index - k)
                + [mth(leaves[:k])])


def verify_inclusion(
    leaf_hash_bytes: bytes,
    leaf_index: int,
    tree_size: int,
    audit_path: list[bytes],
    root_hash: bytes,
) -> bool:
    """Check that `leaf_hash_bytes` is the leaf_hash at `leaf_index`
    in a tree of size `tree_size` whose root is `root_hash`, using
    the proof `audit_path`.

    Stateless + offline — an auditor needs nothing except the proof
    bytes, the trusted root, and this function. That's the property
    that makes Merkle proofs interesting."""
    if not 0 <= leaf_index < tree_size:
        return False
    if tree_size == 1:
        # Single-leaf tree: no siblings, root IS the leaf.
        return not audit_path and leaf_hash_bytes == root_hash

    # Walk up the tree by pairing the running hash with each path
    # sibling, choosing side from the bit pattern of (leaf_index,
    # last_node) as RFC 6962 §2.1.1 describes.
    fn = leaf_index
    sn = tree_size - 1
    current = leaf_hash_bytes
    path_iter = iter(audit_path)

    for sibling in path_iter:
        # If we're at the top of the right subtree (fn is even AND
        # we haven't exhausted the tree), the next sibling is on the
        # right. Otherwise, on the left.
        if sn == 0:
            # Overran the tree → invalid proof.
            return False
        if fn % 2 == 1 or fn == sn:
            # Current node is a right child (or a lone right spine
            # node); pair sibling on the left.
            current = node_hash(sibling, current)
            # Skip subsequent parent nodes that are also right children
            # by shifting until we hit an actual branch.
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            current = node_hash(current, sibling)
        fn >>= 1
        sn >>= 1

    # sn should have reached 0 — meaning we walked up to the root.
    return sn == 0 and current == root_hash


# ── Consistency proof (RFC 6962 §2.1.2) ───────────────────────────

def consistency_path(leaves: list[bytes], first_size: int) -> list[bytes]:
    """PROOF(m, D[n]) per RFC 6962: hashes needed to prove that a
    tree of size `first_size` is a prefix of the current tree
    (built from all `leaves`). Caller must have `0 < first_size <=
    len(leaves)`."""
    n = len(leaves)
    m = first_size
    if m <= 0 or m > n:
        raise ValueError(f"first_size {m} out of (0, {n}]")
    if m == n:
        return []
    return _sub_proof(leaves, m, complete_subtree=True)


def _sub_proof(
    leaves: list[bytes],
    m: int,
    complete_subtree: bool,
) -> list[bytes]:
    """SUBPROOF(m, D[n], b) per RFC 6962 §2.1.2."""
    n = len(leaves)
    if m == n:
        if complete_subtree:
            return []
        return [mth(leaves)]
    # m < n
    k = _largest_power_of_2_lt(n)
    if m <= k:
        return _sub_proof(leaves[:k], m, complete_subtree) + [mth(leaves[k:])]
    else:
        return (_sub_proof(leaves[k:], m - k, complete_subtree=False)
                + [mth(leaves[:k])])


def verify_consistency(
    first_size: int,
    second_size: int,
    first_root: bytes,
    second_root: bytes,
    proof: list[bytes],
) -> bool:
    """Verify that `first_root` (tree of size first_size) is a prefix
    of the tree of size second_size whose root is `second_root`.
    Stateless + offline.

    Implementation strategy: recursively mirror `_sub_proof`'s
    generator logic, rebuilding BOTH the first-tree subtree root
    (r1) and the second-tree root (r2) at each recursion level.
    Consume proof elements left-to-right as the generator produced
    them. At the top, confirm r1 == first_root AND r2 == second_root.

    Slower than an iterative bit-manipulation verifier (it rebuilds
    up to O(log n) hashes), but clearly correct by mirroring the
    proof-generation algorithm exactly. A compliance auditor can
    read this side-by-side with `_sub_proof` and convince themselves
    the code matches RFC 6962 §2.1.2.
    """
    if first_size < 0 or second_size <= 0 or first_size > second_size:
        return False
    if first_size == 0:
        return first_root == empty_tree_hash() and not proof
    if first_size == second_size:
        return not proof and first_root == second_root

    proof_iter = iter(proof)
    try:
        r2_computed, r1_computed = _rebuild_consistency(
            first_size, second_size, complete=True,
            first_root=first_root, proof_iter=proof_iter,
        )
    except StopIteration:
        return False

    # No leftover proof elements.
    try:
        next(proof_iter)
        return False
    except StopIteration:
        pass

    return r1_computed == first_root and r2_computed == second_root


def _rebuild_consistency(
    m: int,
    n: int,
    complete: bool,
    first_root: bytes | None,
    proof_iter,
) -> tuple[bytes, bytes]:
    """Return (r2, r1) at this recursion level — where r1 is the first
    tree's root projected at this subtree, and r2 is the second
    tree's root projected at this subtree. Mirrors `_sub_proof`'s
    recursion exactly so the verifier can be read alongside the
    generator."""
    if m == n:
        if complete:
            # Leaf of the "complete" recursion — this subtree's value
            # is first_root (verified by the caller when it bubbles up).
            assert first_root is not None
            return first_root, first_root
        # Non-complete base case: MTH(D[0:n]) is in the proof explicitly.
        p = next(proof_iter)
        return p, p

    k = _largest_power_of_2_lt(n)
    if m <= k:
        # Left-subtree recurse; right subtree is next proof element.
        left_r2, left_r1 = _rebuild_consistency(
            m, k, complete, first_root, proof_iter,
        )
        right_r2 = next(proof_iter)
        # First tree (only m <= k leaves) is fully in the left subtree.
        return node_hash(left_r2, right_r2), left_r1
    # m > k: right subtree recurses with complete=False (we don't know
    # its projected first-root slot yet — it'll surface as the
    # non-complete base case's explicit element). Left sibling is next
    # proof element.
    right_r2, right_r1 = _rebuild_consistency(
        m - k, n - k, False, None, proof_iter,
    )
    left = next(proof_iter)
    return node_hash(left, right_r2), node_hash(left, right_r1)


# ── Signed Tree Head ──────────────────────────────────────────────
#
# Two signing algorithms supported:
#
#   HMAC-SHA256  — symmetric. Fast, zero-dep (stdlib), back-compat
#                  with every v0.3.0 client. Downside: anyone who
#                  holds the key to verify can also forge. Fine when
#                  the auditor trusts Haldir with the key.
#
#   Ed25519      — asymmetric. Haldir holds the private key; anyone
#                  can verify with just the public key via the JWKS
#                  endpoint. This is the primitive Sigstore/Fulcio
#                  uses for their CT logs, and what lets a customer
#                  prove "Haldir didn't forge this" without holding
#                  any secret Haldir could use against them.
#
# sign_sth dispatches on the key object type. An auditor dispatches
# on the `algorithm` field of the STH dict.

STH_ALGORITHM = "HMAC-SHA256-over-canonical-sth"
STH_ALGORITHM_ED25519 = "Ed25519-over-canonical-sth"


def _canonical_sth(tree_size: int, root_hash: bytes, signed_at: int) -> bytes:
    """The exact bytes that get signed. An auditor reproduces these
    from the published STH fields and re-runs the signature. Same
    canonical form for both HMAC and Ed25519 — only the signing
    algorithm differs."""
    return f"sth:{tree_size}:{root_hash.hex()}:{signed_at}".encode()


def sign_sth(
    tree_size: int,
    root_hash: bytes,
    signing_key: "bytes | Ed25519Private",
    signed_at: int | None = None,
) -> dict:
    """Produce a signed tree head. Returns a serializable dict the
    API can jsonify unchanged.

    Dispatches on `signing_key` type:
      - bytes                → HMAC-SHA256 (back-compat)
      - Ed25519PrivateKey    → Ed25519 signature + key_id (pubkey fpr)
    """
    ts = int(signed_at if signed_at is not None else time.time())
    canonical = _canonical_sth(tree_size, root_hash, ts)

    from cryptography.hazmat.primitives.asymmetric import ed25519
    if isinstance(signing_key, ed25519.Ed25519PrivateKey):
        sig = signing_key.sign(canonical).hex()
        pub = signing_key.public_key().public_bytes_raw()
        return {
            "tree_size":  tree_size,
            "root_hash":  root_hash.hex(),
            "signed_at":  ts,
            "signature":  sig,
            "algorithm":  STH_ALGORITHM_ED25519,
            "public_key": pub.hex(),
            "key_id":     _key_id_for_pubkey(pub),
        }
    # HMAC fallback.
    sig_h = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
    return {
        "tree_size":  tree_size,
        "root_hash":  root_hash.hex(),
        "signed_at":  ts,
        "signature":  sig_h,
        "algorithm":  STH_ALGORITHM,
    }


def verify_sth(sth: dict, signing_key: "bytes | Ed25519Public | None" = None) -> bool:
    """Verify an STH's signature.

    Algorithm dispatch is driven by sth["algorithm"]:
      - HMAC-SHA256-over-canonical-sth     → requires the symmetric key
      - Ed25519-over-canonical-sth         → uses the public key from
                                              the STH itself (or the
                                              caller-pinned one, which
                                              is the secure path)

    For Ed25519, passing None uses the public key embedded in the
    STH. That is NOT a trust root on its own — Haldir could have put
    any key in there. A real auditor pins the public key out of band
    (from /.well-known/jwks.json, saved at enrollment) and passes it
    here so an attacker rewriting the log can't also rewrite the key.
    """
    try:
        canonical = _canonical_sth(
            int(sth["tree_size"]),
            bytes.fromhex(sth["root_hash"]),
            int(sth["signed_at"]),
        )
    except (KeyError, ValueError):
        return False

    algo = sth.get("algorithm", STH_ALGORITHM)

    if algo == STH_ALGORITHM_ED25519:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.exceptions import InvalidSignature
        # Resolve the verification key.
        if signing_key is None:
            pub_hex = sth.get("public_key")
            if not pub_hex:
                return False
            pub_bytes = bytes.fromhex(pub_hex)
        elif isinstance(signing_key, (bytes, bytearray)):
            pub_bytes = bytes(signing_key)
        elif isinstance(signing_key, ed25519.Ed25519PublicKey):
            pub_bytes = signing_key.public_bytes_raw()
        else:
            return False
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub.verify(bytes.fromhex(sth.get("signature", "")), canonical)
            return True
        except (InvalidSignature, ValueError):
            return False

    # HMAC path.
    if signing_key is None or not isinstance(signing_key, (bytes, bytearray)):
        return False
    expected = hmac.new(bytes(signing_key), canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sth.get("signature", ""))


def _key_id_for_pubkey(pub_raw: bytes) -> str:
    """Short, stable identifier for an Ed25519 public key. SHA-256
    of the raw 32-byte pubkey, truncated to 16 hex chars. Lets JWKS
    consumers pin a `key_id` across rotations without the whole key."""
    return hashlib.sha256(pub_raw).hexdigest()[:16]


def derive_signing_key(seed: str) -> bytes:
    """Derive a 256-bit HMAC key from a string seed. Used so
    HALDIR_TREE_SIGNING_KEY can be any printable secret; we
    canonicalize to bytes."""
    return hashlib.sha256(seed.encode()).digest()


def derive_ed25519_key_from_seed(seed: str):
    """Deterministically derive an Ed25519 private key from a string
    seed. Used so HALDIR_TREE_SIGNING_KEY_ED25519_SEED can be any
    printable secret and the same seed always gives the same key
    (survives restarts without operators passing 32-byte raw keys)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    seed_bytes = hashlib.sha256(seed.encode()).digest()  # 32 bytes
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed_bytes)


def load_signing_key_from_env() -> tuple[bytes, str]:
    """Pick the HMAC signing-key source following env precedence:

        HALDIR_TREE_SIGNING_KEY   explicit (preferred)
        HALDIR_ENCRYPTION_KEY     fallback; dual-use of the vault key
        ephemeral                 dev-only; generated on first call

    Returns (key_bytes, source_label). Ephemeral sources make the
    STHs unverifiable across restarts — fine for dev, never for prod.

    For the asymmetric (Ed25519) path, see load_ed25519_signing_key_from_env.
    """
    explicit = os.environ.get("HALDIR_TREE_SIGNING_KEY")
    if explicit:
        return derive_signing_key(explicit), "HALDIR_TREE_SIGNING_KEY"
    fallback = os.environ.get("HALDIR_ENCRYPTION_KEY")
    if fallback:
        return derive_signing_key("haldir-tree:" + fallback), "HALDIR_ENCRYPTION_KEY"
    # Ephemeral — per-process, not persisted.
    if not hasattr(load_signing_key_from_env, "_ephemeral"):
        load_signing_key_from_env._ephemeral = os.urandom(32)  # type: ignore[attr-defined]
    return load_signing_key_from_env._ephemeral, "ephemeral"  # type: ignore[attr-defined]


def load_ed25519_signing_key_from_env():
    """Pick the Ed25519 signing key following env precedence:

        HALDIR_TREE_SIGNING_KEY_ED25519         base64url(32-byte-raw)
        HALDIR_TREE_SIGNING_KEY_ED25519_SEED    arbitrary string → SHA-256 → private key
        HALDIR_TREE_SIGNING_KEY                 fallback: derive from HMAC seed
        ephemeral                                dev-only; generated on first call

    Returns (Ed25519PrivateKey, source_label). The returned private
    key has a public_key() whose raw bytes go into the JWKS endpoint.
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric import ed25519

    raw_b64 = os.environ.get("HALDIR_TREE_SIGNING_KEY_ED25519", "").strip()
    if raw_b64:
        try:
            raw = base64.urlsafe_b64decode(raw_b64 + "==")
            if len(raw) == 32:
                return (
                    ed25519.Ed25519PrivateKey.from_private_bytes(raw),
                    "HALDIR_TREE_SIGNING_KEY_ED25519",
                )
        except (ValueError, Exception):
            pass  # fall through to seed / ephemeral

    seed = os.environ.get("HALDIR_TREE_SIGNING_KEY_ED25519_SEED", "").strip()
    if seed:
        return (
            derive_ed25519_key_from_seed(seed),
            "HALDIR_TREE_SIGNING_KEY_ED25519_SEED",
        )

    # Reuse the HMAC seed if the operator set one — gives a stable key
    # across restarts without separate configuration.
    hmac_explicit = os.environ.get("HALDIR_TREE_SIGNING_KEY", "").strip()
    if hmac_explicit:
        return (
            derive_ed25519_key_from_seed("haldir-ed25519:" + hmac_explicit),
            "HALDIR_TREE_SIGNING_KEY (reused seed)",
        )

    # Ephemeral — per-process, generated once and cached on the function.
    if not hasattr(load_ed25519_signing_key_from_env, "_ephemeral"):
        load_ed25519_signing_key_from_env._ephemeral = (  # type: ignore[attr-defined]
            ed25519.Ed25519PrivateKey.generate()
        )
    return (
        load_ed25519_signing_key_from_env._ephemeral,  # type: ignore[attr-defined]
        "ephemeral",
    )


# ── Proof serialization (for HTTP + SDK + tests) ──────────────────

def proof_to_hex(proof: list[bytes]) -> list[str]:
    """Hex-encode each sibling hash for JSON transport."""
    return [h.hex() for h in proof]


def proof_from_hex(hexes: Iterable[str]) -> list[bytes]:
    """Parse hex-encoded proof elements back into bytes. Raises
    ValueError on malformed input."""
    out = []
    for h in hexes:
        out.append(bytes.fromhex(h))
    return out


# ── Convenience: one-shot proof generation + verification ─────────

def generate_inclusion_proof(
    leaves: list[bytes],
    index: int,
) -> dict:
    """High-level convenience: builds the tree, extracts the proof,
    packages into a self-describing dict that verify_inclusion_hex
    can consume directly."""
    root = mth(leaves)
    path = inclusion_path(leaves, index)
    return {
        "leaf_index":  index,
        "leaf_hash":   leaves[index].hex(),
        "tree_size":   len(leaves),
        "root_hash":   root.hex(),
        "audit_path":  proof_to_hex(path),
        "algorithm":   "RFC6962-SHA256",
    }


def verify_inclusion_hex(proof: dict) -> bool:
    """Parse a hex-serialized proof dict and verify. Returns True iff
    the proof's leaf_hash is at leaf_index in the tree of size
    tree_size whose root is root_hash."""
    try:
        leaf_hash_bytes = bytes.fromhex(proof["leaf_hash"])
        root_hash_bytes = bytes.fromhex(proof["root_hash"])
        audit_path = proof_from_hex(proof["audit_path"])
        leaf_index = int(proof["leaf_index"])
        tree_size  = int(proof["tree_size"])
    except (KeyError, ValueError, TypeError):
        return False
    return verify_inclusion(
        leaf_hash_bytes, leaf_index, tree_size, audit_path, root_hash_bytes,
    )


def verify_consistency_hex(proof: dict) -> bool:
    """Parse a hex-serialized consistency-proof dict and verify."""
    try:
        first_size  = int(proof["first_size"])
        second_size = int(proof["second_size"])
        first_root  = bytes.fromhex(proof["first_root"])
        second_root = bytes.fromhex(proof["second_root"])
        path        = proof_from_hex(proof["consistency_path"])
    except (KeyError, ValueError, TypeError):
        return False
    return verify_consistency(
        first_size, second_size, first_root, second_root, path,
    )
