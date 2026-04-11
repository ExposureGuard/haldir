"""
Haldir Vault — Encrypted secrets and payment authorization with persistent storage.
"""

import json
import time
from dataclasses import dataclass, field
from cryptography.fernet import Fernet


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


class Vault:
    """Encrypted secrets manager with persistent storage."""

    def __init__(self, encryption_key: bytes | None = None, db_path: str | None = None):
        if encryption_key:
            self._key = encryption_key
            self._fernet = Fernet(encryption_key)
        else:
            self._key = Fernet.generate_key()
            self._fernet = Fernet(self._key)
        self._db_path = db_path
        self._secrets: dict[str, SecretEntry] = {}

    @property
    def encryption_key(self) -> bytes:
        return self._key

    def _get_db(self):
        if not self._db_path:
            return None
        from haldir_db import get_db
        return get_db(self._db_path)

    def store_secret(self, name: str, value: str, scope_required: str = "read",
                     metadata: dict | None = None, tenant_id: str = "") -> SecretEntry:
        encrypted = self._fernet.encrypt(value.encode())
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

    def get_secret(self, name: str, session=None, tenant_id: str = "") -> str | None:
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

        return self._fernet.decrypt(entry.encrypted_value).decode()

    def delete_secret(self, name: str, tenant_id: str = "") -> bool:
        cache_key = f"{tenant_id}:{name}"
        deleted = cache_key in self._secrets
        self._secrets.pop(cache_key, None)

        conn = self._get_db()
        if conn:
            conn.execute("DELETE FROM secrets WHERE name = ? AND tenant_id = ?", (name, tenant_id))
            conn.commit()
            conn.close()
            return True
        return deleted

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

    def authorize_payment(self, session, amount: float, currency: str = "USD",
                          description: str = "") -> dict:
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
