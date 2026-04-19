"""
Haldir Vault — AES-256-GCM encrypted secrets and payment authorization
with persistent storage.

Encryption: AES-256-GCM (authenticated encryption with associated data).
  - 256-bit key (32 bytes), base64url-encoded in env vars
  - 96-bit nonce (12 bytes), randomly generated per encryption
  - 128-bit authentication tag appended to ciphertext (handled by AESGCM)
  - Storage format: nonce (12 bytes) || ciphertext_with_tag

Prior versions used Fernet (AES-128-CBC + HMAC-SHA256). Existing deployments
must rotate secrets after upgrading.
"""

import base64
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from haldir_tracing import traced_span


NONCE_LEN = 12  # 96 bits, NIST-recommended for AES-GCM
KEY_LEN = 32    # 256 bits


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


class Vault:
    """Encrypted secrets manager with persistent storage (AES-256-GCM)."""

    def __init__(self, encryption_key: bytes | str | None = None,
                 db_path: str | None = None):
        if encryption_key:
            self._raw_key = _decode_key(encryption_key)
        else:
            self._raw_key = os.urandom(KEY_LEN)
        self._aesgcm = AESGCM(self._raw_key)
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
        """Encrypt bytes; return nonce || ciphertext_with_tag."""
        nonce = os.urandom(NONCE_LEN)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad or None)
        return nonce + ciphertext

    def _decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        """Decrypt nonce || ciphertext_with_tag."""
        if len(blob) < NONCE_LEN + 16:  # nonce + min tag size
            raise ValueError("ciphertext too short to be a valid AES-GCM blob")
        nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
        return self._aesgcm.decrypt(nonce, ciphertext, aad or None)

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

    def authorize_payment(self, session: Any, amount: float, currency: str = "USD",
                          description: str = "") -> dict[str, Any]:
        if not session.is_valid:
            return {"authorized": False, "reason": "Session invalid or expired"}

        if not session.authorize_spend(amount):
            return {
                "authorized": False,
                "reason": f"Insufficient budget. Remaining: ${session.remaining_budget:.2f}, requested: ${amount:.2f}",
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

        tenant_id = getattr(session, "tenant_id", "")

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT INTO payments (authorization_id, tenant_id, session_id, agent_id, amount, currency, description, remaining_budget, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (auth_id, tenant_id, session.session_id, session.agent_id, amount, currency, description, session.remaining_budget, time.time())
            )
            conn.execute("UPDATE sessions SET spent = ? WHERE session_id = ? AND tenant_id = ?",
                         (session.spent, session.session_id, tenant_id))
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
