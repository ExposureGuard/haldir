"""
Haldir Vault — AES-256-GCM encrypted secrets and payment authorization
with persistent storage.

Encryption: AES-256-GCM (authenticated encryption with associated data).
  - 256-bit key (32 bytes), base64url-encoded in env vars
  - 96-bit nonce (12 bytes), randomly generated per encryption
  - 128-bit authentication tag appended to ciphertext (handled by AESGCM)
  - Storage format: see BLOB FORMAT below

BLOB FORMAT
    v1:     "HDLR" | version(1) | key_id(8) | nonce(12) | ciphertext_with_tag
    legacy: nonce(12) | ciphertext_with_tag

The key_id names the key that produced the ciphertext, so the vault can hold
several keys at once and re-encrypt in place. Without it a rotation would be
a one-way door: nothing in the row would say which key opens it.

Legacy blobs carry no key_id — they predate the header — so they are opened
with `legacy_key`. A rotation rewrites every blob it touches into v1, so a
vault that has been rotated even once has no legacy blobs left and can hold
any number of keys.

Prior versions used Fernet (AES-128-CBC + HMAC-SHA256); that is a different
format again and is not readable here. Deployments upgrading from it must
re-store their secrets from source.
"""

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from haldir_tracing import traced_span


NONCE_LEN = 12  # 96 bits, NIST-recommended for AES-GCM
KEY_LEN = 32    # 256 bits
TAG_LEN = 16    # AES-GCM authentication tag

MAGIC = b"HDLR"
BLOB_VERSION = 1
KEY_ID_LEN = 8
HEADER_LEN = len(MAGIC) + 1 + KEY_ID_LEN  # 13


def key_id_for(key: bytes | str) -> str:
    """A short, stable, non-reversible name for a key.

    It is a label, not a secret: it appears in blobs, logs, and rotation
    reports, so it must be safe to print. Truncated SHA-256 of the key means
    two different keys collide with probability ~2^-64.

    Accepts a key in any form `_decode_key` does — raw 32 bytes or the
    base64url text that `generate_key()` and the environment produce.
    Hashing the base64 text of a key and hashing the key itself give
    different ids, which is a silent way to compare a key against itself
    and be told they differ.
    """
    return hashlib.sha256(_decode_key(key)).hexdigest()[: KEY_ID_LEN * 2]


def _parse_blob(blob: bytes) -> tuple[str, bytes, bytes]:
    """Split a stored blob into (key_id, nonce, ciphertext).

    Returns key_id "" for a legacy headerless blob. A legacy blob's first
    bytes are a random nonce, so it can only be mistaken for a v1 blob if
    that nonce happens to begin with the magic and a valid version byte
    (probability ~2^-32 per secret); the length check below is a further
    guard, and `legacy_key` is present in any vault that could still hold
    one.
    """
    if not blob:
        raise ValueError("empty ciphertext blob")

    if blob[: len(MAGIC)] == MAGIC and len(blob) > HEADER_LEN + TAG_LEN:
        version = blob[len(MAGIC)]
        if version == BLOB_VERSION:
            kid = blob[len(MAGIC) + 1 : len(MAGIC) + 1 + KEY_ID_LEN]
            return kid.hex(), blob[HEADER_LEN : HEADER_LEN + NONCE_LEN], blob[HEADER_LEN + NONCE_LEN :]
        raise ValueError(
            f"ciphertext blob declares format version {version}, but this "
            f"build understands 1. Upgrade Haldir, or restore the blob with "
            f"the build that wrote it."
        )

    if len(blob) < NONCE_LEN + TAG_LEN:
        raise ValueError("ciphertext too short to be a valid AES-GCM blob")
    return "", blob[:NONCE_LEN], blob[NONCE_LEN:]


def _seal(key: bytes, kid: str, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt with `key` and return a v1 blob naming it.

    The nonce is generated once and both stored and used. Generating it at
    each site — as the first draft of the rotation code did — yields a blob
    that no key can open, and only at the moment someone needs the secret.
    """
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    return MAGIC + bytes([BLOB_VERSION]) + bytes.fromhex(kid) + nonce + ciphertext


@dataclass
class Keyring:
    """The set of keys a vault can decrypt with, exactly one of which is
    primary. A vault holds more than one key only during a rotation, or
    after one, when the retired key is still needed for blobs that have not
    been rewritten yet.

    `legacy_key` opens blobs written before the format carried a key id.
    There is at most one, because such blobs say nothing about which key
    made them — a second headerless key would be indistinguishable from the
    first. Rotating retires that constraint by rewriting them.
    """

    primary: bytes
    others: dict[str, bytes] = field(default_factory=dict)  # key_id -> key
    legacy_key: bytes | None = None

    @property
    def primary_id(self) -> str:
        return key_id_for(self.primary)

    def all_keys(self) -> dict[str, bytes]:
        """Every key, by id, primary included."""
        return {self.primary_id: self.primary, **self.others}

    def key_for(self, kid: str) -> bytes | None:
        """The key named `kid`, or the legacy key when `kid` is empty."""
        if not kid:
            return self.legacy_key
        return self.all_keys().get(kid)

    def describe(self) -> list[dict[str, Any]]:
        """Rotation report material. Never includes key bytes."""
        rows = [{"key_id": self.primary_id, "role": "primary"}]
        rows += [{"key_id": k, "role": "retired"} for k in sorted(self.others)]
        if self.legacy_key is not None:
            rows.append({"key_id": "(legacy, headerless)", "role": "legacy"})
        return rows


@dataclass
class SecretEntry:
    name: str
    encrypted_value: bytes
    scope_required: str = "read"
    created_at: float = field(default_factory=time.time)
    last_accessed: float = 0.0
    access_count: int = 0
    metadata: dict = field(default_factory=dict)
    tenant_id: str = ""


def _decode_key(key: bytes | str) -> bytes:
    """Accept either raw 32-byte keys or base64url-encoded keys."""
    if isinstance(key, str):
        key = key.encode()
    # Raw 32-byte key passed through
    if len(key) == KEY_LEN:
        return key
    # Assume base64url-encoded
    try:
        decoded = base64.urlsafe_b64decode(key)
    except Exception as e:
        raise ValueError(
            f"HALDIR_ENCRYPTION_KEY could not be decoded. Expected 32 raw bytes "
            f"or base64url-encoded 32 bytes. Got length {len(key)}. "
            f"Generate a valid key with: Vault.generate_key()"
        ) from e
    if len(decoded) != KEY_LEN:
        raise ValueError(
            f"HALDIR_ENCRYPTION_KEY decoded to {len(decoded)} bytes, "
            f"expected {KEY_LEN} (256 bits). Generate a valid key with: "
            f"Vault.generate_key()"
        )
    return decoded


def _previous_keys_from_env() -> list[bytes | str]:
    """Retired keys, newest first, from HALDIR_ENCRYPTION_KEY_PREVIOUS.

    Comma-separated so a vault that has rotated twice can still open the
    oldest blobs. Whitespace and empty entries are ignored, so a trailing
    comma does not produce a spurious "invalid key" warning.
    """
    raw = os.environ.get("HALDIR_ENCRYPTION_KEY_PREVIOUS", "")
    return [k.strip() for k in raw.split(",") if k.strip()]


class Vault:
    """Encrypted secrets manager with persistent storage (AES-256-GCM)."""

    def __init__(self, encryption_key: bytes | str | None = None,
                 db_path: str | None = None,
                 previous_keys: list[bytes | str] | None = None,
                 legacy_key: bytes | str | None = None):
        # `previous_keys` and `legacy_key` default from the environment so an
        # operator can complete a rotation by changing env vars alone — the
        # process must be able to read the old ciphertext again after a
        # restart, and a rotation that only lived in memory would strand it.
        if previous_keys is None:
            previous_keys = _previous_keys_from_env()
        if legacy_key is None:
            legacy_key = os.environ.get("HALDIR_ENCRYPTION_KEY_LEGACY") or None

        if encryption_key:
            primary = _decode_key(encryption_key)
        else:
            primary = os.urandom(KEY_LEN)

        others: dict[str, bytes] = {}
        for k in previous_keys:
            raw = _decode_key(k)
            kid = key_id_for(raw)
            if kid != key_id_for(primary):
                others[kid] = raw

        self._keyring = Keyring(
            primary=primary,
            others=others,
            legacy_key=_decode_key(legacy_key) if legacy_key else None,
        )
        self._raw_key = primary
        self._aesgcm = AESGCM(primary)
        self._db_path = db_path
        self._secrets: dict[str, SecretEntry] = {}

    @classmethod
    def generate_key(cls) -> bytes:
        """Generate a fresh base64url-encoded 256-bit key (env-var friendly)."""
        return base64.urlsafe_b64encode(os.urandom(KEY_LEN))

    @property
    def encryption_key(self) -> bytes:
        """Return the current key in base64url form (for persisting to .env)."""
        return base64.urlsafe_b64encode(self._raw_key)

    def _encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt bytes with the primary key; return a v1 blob."""
        return _seal(self._keyring.primary, self._keyring.primary_id, plaintext, aad)

    def _open(self, blob: bytes, aad: bytes = b"",
              keyring: "Keyring | None" = None) -> bytes:
        """Decrypt a stored blob, resolving which key it needs.

        One resolver, used by both reads and rotation. Two call sites that
        each decide for themselves which key to use is how rotation came to
        reject every legacy blob that reading had just learned to open.

        Raises a message that says what to do when the needed key is absent —
        an operator who has dropped a key from the environment needs to be
        told that, not handed an InvalidTag.
        """
        kr = keyring or self._keyring
        kid, nonce, ciphertext = _parse_blob(blob)

        if not kid and kr.legacy_key is None:
            # Headerless: written before the format carried a key id, so
            # nothing in the row says which key made it. On the ordinary
            # upgrade that key is the one the vault is *currently* started
            # with — the operator changed no configuration — so try the
            # primary before complaining. Trying it costs one failed
            # authentication when the guess is wrong, and is the difference
            # between an upgrade that works and one that strands every secret
            # the deployment owns.
            try:
                return AESGCM(kr.primary).decrypt(nonce, ciphertext, aad or None)
            except InvalidTag:
                pass  # fall through to the diagnosis below
            raise ValueError(
                "this secret was encrypted before Haldir tagged ciphertext "
                "with a key id, and the vault's current key does not open it. "
                "If the key was rotated or replaced, set "
                "HALDIR_ENCRYPTION_KEY_LEGACY to the key that was primary "
                "before the upgrade, then run a rotation to rewrite it."
            )

        key = kr.key_for(kid)
        if key is None:
            raise ValueError(
                f"no key available for key_id {kid}. It was removed from "
                f"HALDIR_ENCRYPTION_KEY_PREVIOUS while secrets encrypted with "
                f"it still exist. Restore the key and run a rotation before "
                f"retiring it."
            )
        return AESGCM(key).decrypt(nonce, ciphertext, aad or None)

    def _decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        return self._open(blob, aad)

    def _get_db(self) -> Any:
        if not self._db_path:
            return None
        from haldir_db import get_db
        return get_db(self._db_path)

    @traced_span("haldir.vault.store_secret")
    def store_secret(self, name: str, value: str, scope_required: str = "read",
                     metadata: dict | None = None, tenant_id: str = "") -> SecretEntry:
        # Bind ciphertext to the (tenant, name) pair via AAD: swapping
        # ciphertext between tenants or secret names will fail authentication.
        aad = f"{tenant_id}:{name}".encode()
        encrypted = self._encrypt(value.encode(), aad=aad)
        entry = SecretEntry(
            name=name,
            encrypted_value=encrypted,
            scope_required=scope_required,
            metadata=metadata or {},
            tenant_id=tenant_id,
        )
        self._secrets[f"{tenant_id}:{name}"] = entry

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT OR REPLACE INTO secrets (name, tenant_id, encrypted_value, scope_required, created_at, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, tenant_id, encrypted, scope_required, entry.created_at, json.dumps(metadata or {}))
            )
            conn.commit()
            conn.close()
        return entry

    @traced_span("haldir.vault.get_secret")
    def get_secret(self, name: str, session: Optional[Any] = None,
                   tenant_id: str = "") -> Optional[str]:
        cache_key = f"{tenant_id}:{name}"
        entry = self._secrets.get(cache_key)

        if not entry:
            conn = self._get_db()
            if conn:
                row = conn.execute(
                    "SELECT * FROM secrets WHERE name = ? AND tenant_id = ?",
                    (name, tenant_id)
                ).fetchone()
                conn.close()
                if row:
                    entry = SecretEntry(
                        name=row["name"],
                        encrypted_value=row["encrypted_value"],
                        scope_required=row["scope_required"],
                        created_at=row["created_at"],
                        last_accessed=row["last_accessed"],
                        access_count=row["access_count"],
                        tenant_id=tenant_id,
                    )
                    self._secrets[cache_key] = entry

        if not entry:
            return None

        if session:
            if not session.is_valid:
                raise PermissionError(f"Session {session.session_id} is not valid")
            if not session.has_permission(entry.scope_required):
                raise PermissionError(
                    f"Session lacks '{entry.scope_required}' scope for secret '{name}'"
                )

        entry.last_accessed = time.time()
        entry.access_count += 1

        conn = self._get_db()
        if conn:
            conn.execute(
                "UPDATE secrets SET last_accessed = ?, access_count = ? WHERE name = ? AND tenant_id = ?",
                (entry.last_accessed, entry.access_count, name, tenant_id))
            conn.commit()
            conn.close()

        aad = f"{tenant_id}:{name}".encode()
        return self._decrypt(entry.encrypted_value, aad=aad).decode()

    def delete_secret(self, name: str, tenant_id: str = "") -> bool:
        """Return True iff a secret was actually deleted. Callers rely
        on this to produce a 404 when the target didn't exist (SDK
        contract + test_sdk.test_delete_missing_secret_404)."""
        cache_key = f"{tenant_id}:{name}"
        cache_hit = cache_key in self._secrets
        self._secrets.pop(cache_key, None)

        conn = self._get_db()
        if conn:
            cur = conn.execute(
                "DELETE FROM secrets WHERE name = ? AND tenant_id = ?",
                (name, tenant_id),
            )
            conn.commit()
            rowcount = cur.rowcount
            conn.close()
            return rowcount > 0 or cache_hit
        return cache_hit

    def list_secrets(self, tenant_id: str = "") -> list[str]:
        names = set()
        for key, entry in self._secrets.items():
            if entry.tenant_id == tenant_id:
                names.add(entry.name)
        conn = self._get_db()
        if conn:
            rows = conn.execute("SELECT name FROM secrets WHERE tenant_id = ?", (tenant_id,)).fetchall()
            conn.close()
            names.update(r["name"] for r in rows)
        return sorted(names)

    # ── Key rotation ─────────────────────────────────────────────────

    def _stored_secrets(self) -> list[tuple[str, str, bytes]]:
        """Every stored secret as (tenant_id, name, blob), DB first so a
        stale cache entry cannot hide a blob that still needs rewriting."""
        rows: dict[tuple[str, str], bytes] = {}
        conn = self._get_db()
        if conn:
            for r in conn.execute("SELECT tenant_id, name, encrypted_value FROM secrets").fetchall():
                rows[(r["tenant_id"] or "", r["name"])] = bytes(r["encrypted_value"])
            conn.close()
        for entry in self._secrets.values():
            rows.setdefault((entry.tenant_id or "", entry.name), entry.encrypted_value)
        return [(t, n, blob) for (t, n), blob in sorted(rows.items())]

    def key_census(self) -> dict[str, Any]:
        """Which keys the stored blobs actually need, and how many each.

        This is the question an operator asks before retiring a key, and the
        answer has to come from the ciphertext rather than from configuration
        — a key is only safe to drop when no blob names it.
        """
        counts: dict[str, int] = {}
        unreadable = 0
        for _tenant, _name, blob in self._stored_secrets():
            try:
                kid, _nonce, _ct = _parse_blob(blob)
            except ValueError:
                unreadable += 1
                continue
            label = kid or "(legacy, headerless)"
            counts[label] = counts.get(label, 0) + 1
        return {
            "keys": self._keyring.describe(),
            "blobs_by_key": counts,
            "unreadable_blobs": unreadable,
            "total_blobs": sum(counts.values()) + unreadable,
        }

    def rotate_keys(self, new_key: bytes | str, *, dry_run: bool = False) -> dict[str, Any]:
        """Re-encrypt every secret under `new_key`, leaving the old key in
        place so nothing becomes unreadable mid-flight.

        Safe to interrupt and re-run. Each secret is rewritten in its own
        write, and until every one has been rewritten the old key is still
        in the keyring, so a crash halfway leaves a vault that reads
        correctly under both keys rather than one that reads under neither.
        Re-running finishes the job; the second pass is a no-op.

        Retiring the old key is a separate, deliberate act: run this, confirm
        `key_census()` reports no blobs under the old id, and only then remove
        it from HALDIR_ENCRYPTION_KEY_PREVIOUS.
        """
        new_raw = _decode_key(new_key)
        new_id = key_id_for(new_raw)

        # The new keyring keeps every currently-readable key AND the new one,
        # so in-flight decryption during the pass cannot fail on a key we are
        # partway through retiring.
        working = Keyring(
            primary=new_raw,
            # Everything currently readable, minus the new key if it is
            # already among them. Filtering on the NEW key's id is the point:
            # filtering on the old one drops the very key the blobs about to
            # be rewritten are encrypted under, and every one of them then
            # fails as "key removed".
            others={k: v for k, v in self._keyring.all_keys().items() if k != new_id},
            legacy_key=self._keyring.legacy_key,
        )

        report: dict[str, Any] = {
            "new_key_id": new_id,
            "previous_key_id": self._keyring.primary_id,
            "dry_run": dry_run,
            "rotated": [],
            "already_current": [],
            "failed": [],
        }

        for tenant_id, name, blob in self._stored_secrets():
            try:
                kid, _nonce, _ct = _parse_blob(blob)
                if kid == new_id:
                    report["already_current"].append({"tenant_id": tenant_id, "name": name})
                    continue
                # AAD is recomputed, not carried: it is derived from the
                # (tenant, name) pair, which is exactly what re-binding means.
                aad = f"{tenant_id}:{name}".encode()
                # Same resolver reads use, so a blob that can be read can
                # always be rotated. Headerless blobs land here too, and get
                # rewritten into the tagged format.
                plaintext = self._open(blob, aad, keyring=working)
                new_blob = _seal(new_raw, new_id, plaintext, aad)
            except Exception as e:  # noqa: BLE001 — one bad secret must not
                # abort the rotation of every other secret.
                report["failed"].append({
                    "tenant_id": tenant_id, "name": name,
                    "error": f"{type(e).__name__}: {e}",
                })
                continue

            if dry_run:
                report["rotated"].append({"tenant_id": tenant_id, "name": name})
                continue

            if not self._write_blob(tenant_id, name, new_blob):
                report["failed"].append({
                    "tenant_id": tenant_id, "name": name,
                    "error": "re-encrypted, but the write did not reach storage",
                })
                continue

            cached = self._secrets.get(f"{tenant_id}:{name}")
            if cached is not None:
                cached.encrypted_value = new_blob
            report["rotated"].append({"tenant_id": tenant_id, "name": name})

        # Only adopt the new key as primary once the pass is done. If it
        # raised, the vault is left on the key it was already using.
        if not dry_run:
            self._keyring = working
            self._raw_key = new_raw
            self._aesgcm = AESGCM(new_raw)

        report["summary"] = {
            "rotated": len(report["rotated"]),
            "already_current": len(report["already_current"]),
            "failed": len(report["failed"]),
        }
        return report

    def rotate_to_primary(self, *, dry_run: bool = False) -> dict[str, Any]:
        """Re-encrypt every secret under the vault's current primary key.

        This is the flow an operator actually runs, and the only one that
        belongs behind an HTTP endpoint: the new key is placed in
        HALDIR_ENCRYPTION_KEY, the old one in HALDIR_ENCRYPTION_KEY_PREVIOUS,
        the process restarts, and this call finishes the re-encryption. The
        key is never transmitted — an endpoint that accepted a key in its
        body would put that key in proxy logs, request captures, and shell
        history.
        """
        return self.rotate_keys(self._keyring.primary, dry_run=dry_run)

    def _write_blob(self, tenant_id: str, name: str, blob: bytes) -> bool:
        conn = self._get_db()
        if not conn:
            return True  # in-memory vault; the cache update in the caller is the write
        cur = conn.execute(
            "UPDATE secrets SET encrypted_value = ? WHERE name = ? AND tenant_id = ?",
            (blob, name, tenant_id),
        )
        conn.commit()
        changed = cur.rowcount
        conn.close()
        return bool(changed)

    def authorize_payment(self, session: Any, amount: float, currency: str = "USD",
                          description: str = "") -> dict[str, Any]:
        if not session.is_valid:
            return {"authorized": False, "reason": "Session invalid or expired"}

        amount = float(amount)
        tenant_id = getattr(session, "tenant_id", "")

        # Claim the budget first, in a single statement. The check and the
        # increment used to be two — authorize_spend() up here, the UPDATE
        # down at the bottom — which let concurrent callers each read the
        # same starting balance and each conclude they were within it.
        conn = self._get_db()
        if conn:
            from haldir_gate import reserve_spend
            granted = reserve_spend(conn, session.session_id, tenant_id, amount)
            conn.commit()
            conn.close()
        else:
            # No database to serialize against, so the in-process session is
            # the only state there is. Single writer by construction.
            granted = session.authorize_spend(amount)

        if not granted:
            return {
                "authorized": False,
                "reason": (
                    f"Insufficient budget. Remaining: "
                    f"${session.remaining_budget:.2f}, requested: ${amount:.2f}"
                ),
            }

        session.record_spend(amount)
        import secrets as _secrets
        auth_id = f"auth_{_secrets.token_urlsafe(16)}"
        record = {
            "authorized": True,
            "authorization_id": auth_id,
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "amount": amount,
            "currency": currency,
            "description": description,
            "remaining_budget": session.remaining_budget,
            "timestamp": time.time(),
        }

        conn = self._get_db()
        if conn:
            # The budget was already claimed by reserve_spend. This only
            # records the payment — writing `spent` a second time here
            # would set it from this process's view and undo the atomicity
            # that reserve_spend exists to provide.
            conn.execute(
                "INSERT INTO payments (authorization_id, tenant_id, session_id, agent_id, amount, currency, description, remaining_budget, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (auth_id, tenant_id, session.session_id, session.agent_id, amount, currency, description, session.remaining_budget, time.time())
            )
            conn.commit()
            conn.close()

        return record

    def get_payment_log(self, session_id: str | None = None, tenant_id: str = "") -> list[dict]:
        conn = self._get_db()
        if conn:
            if session_id:
                rows = conn.execute(
                    "SELECT * FROM payments WHERE session_id = ? AND tenant_id = ? ORDER BY timestamp DESC",
                    (session_id, tenant_id)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM payments WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT 100",
                    (tenant_id,)).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        return []
