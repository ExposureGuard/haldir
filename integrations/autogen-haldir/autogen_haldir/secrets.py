"""Access Haldir-stored secrets without exposing them to the LLM context."""

from __future__ import annotations

from pydantic import SecretStr

from sdk.client import HaldirClient


class HaldirSecrets:
    """Fetch secrets from Haldir's AES-256-GCM vault with scope enforcement.

    Raw values are wrapped in `pydantic.SecretStr` so they won't appear
    in logs, tracebacks, or `repr()` output by default. Call
    `.get_secret_value()` to unwrap only where the value is actually used.
    """

    def __init__(self, client: HaldirClient, session_id: str):
        self.client = client
        self.session_id = session_id

    def get(self, name: str) -> SecretStr:
        """Retrieve a secret by name. Raises `HaldirPermissionError` if out-of-scope."""
        result = self.client.get_secret(name, session_id=self.session_id)
        return SecretStr(result["value"])
