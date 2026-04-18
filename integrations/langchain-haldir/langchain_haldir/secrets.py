"""
HaldirSecrets — fetch secrets from the Haldir vault and get LangChain SecretStr.

Agents should never see raw credentials. This helper retrieves secrets under
a Haldir session (scope-checked server-side) and returns them as LangChain
SecretStr so they mask in logs and repr output.
"""

from __future__ import annotations

from pydantic import SecretStr

from sdk.client import HaldirClient


class HaldirSecrets:
    """Scope-checked secret retrieval bound to a Haldir session.

    Args:
        client: Authenticated HaldirClient.
        session_id: Active Haldir session to use for scope enforcement.
    """

    def __init__(self, client: HaldirClient, session_id: str) -> None:
        self.client = client
        self.session_id = session_id

    def get(self, name: str) -> SecretStr:
        """Return the secret value as a LangChain-friendly SecretStr.

        Raises HaldirPermissionError if the session's scopes don't satisfy
        the secret's scope_required.
        """
        resp = self.client.get_secret(name, session_id=self.session_id)
        return SecretStr(resp["value"])

    def get_raw(self, name: str) -> str:
        """Return the raw secret string. Avoid — prefer get() + SecretStr."""
        resp = self.client.get_secret(name, session_id=self.session_id)
        return resp["value"]
