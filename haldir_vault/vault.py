"""
Haldir Vault — Encrypted secrets storage and payment authorization.

Secrets are encrypted at rest using Fernet (AES-128-CBC).
Agents request secrets by name; Vault checks the session's scopes
before returning the decrypted value.
"""

import time
from dataclasses import dataclass, field
from cryptography.fernet import Fernet


@dataclass
class SecretEntry:
    name: str
    encrypted_value: bytes
    scope_required: str = "read"     # Permission needed to access this secret
    created_at: float = field(default_factory=time.time)
    last_accessed: float = 0.0
    access_count: int = 0
    metadata: dict = field(default_factory=dict)


class Vault:
    """
    Encrypted secrets manager for AI agents.

    Secrets are stored encrypted. Access requires a valid Gate session
    with the appropriate scope.
    """

    def __init__(self, encryption_key: bytes | None = None):
        if encryption_key:
            self._fernet = Fernet(encryption_key)
        else:
            self._key = Fernet.generate_key()
            self._fernet = Fernet(self._key)
        self._secrets: dict[str, SecretEntry] = {}
        self._payment_log: list[dict] = []

    @property
    def encryption_key(self) -> bytes:
        return self._key

    def store_secret(self, name: str, value: str, scope_required: str = "read",
                     metadata: dict | None = None) -> SecretEntry:
        """Store an encrypted secret."""
        encrypted = self._fernet.encrypt(value.encode())
        entry = SecretEntry(
            name=name,
            encrypted_value=encrypted,
            scope_required=scope_required,
            metadata=metadata or {},
        )
        self._secrets[name] = entry
        return entry

    def get_secret(self, name: str, session=None) -> str | None:
        """
        Retrieve a decrypted secret.

        If a session is provided, checks that the session has the required scope.
        """
        entry = self._secrets.get(name)
        if not entry:
            return None

        # Check session permissions if provided
        if session:
            if not session.is_valid:
                raise PermissionError(f"Session {session.session_id} is not valid")
            if not session.has_permission(entry.scope_required):
                raise PermissionError(
                    f"Session lacks '{entry.scope_required}' scope for secret '{name}'"
                )

        entry.last_accessed = time.time()
        entry.access_count += 1
        return self._fernet.decrypt(entry.encrypted_value).decode()

    def delete_secret(self, name: str) -> bool:
        """Remove a secret from the vault."""
        if name in self._secrets:
            del self._secrets[name]
            return True
        return False

    def list_secrets(self) -> list[str]:
        """List secret names (never values)."""
        return list(self._secrets.keys())

    def authorize_payment(self, session, amount: float, currency: str = "USD",
                          description: str = "") -> dict:
        """
        Authorize a payment against a session's budget.

        Returns an authorization record (not an actual charge — that's
        the external payment provider's job).
        """
        if not session.is_valid:
            return {"authorized": False, "reason": "Session invalid or expired"}

        if not session.authorize_spend(amount):
            return {
                "authorized": False,
                "reason": f"Insufficient budget. Remaining: ${session.remaining_budget:.2f}, requested: ${amount:.2f}",
            }

        session.record_spend(amount)
        record = {
            "authorized": True,
            "authorization_id": f"auth_{int(time.time())}_{len(self._payment_log)}",
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "amount": amount,
            "currency": currency,
            "description": description,
            "remaining_budget": session.remaining_budget,
            "timestamp": time.time(),
        }
        self._payment_log.append(record)
        return record

    def get_payment_log(self, session_id: str | None = None) -> list[dict]:
        """Get payment authorization history."""
        if session_id:
            return [p for p in self._payment_log if p["session_id"] == session_id]
        return list(self._payment_log)
