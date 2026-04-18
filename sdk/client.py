"""
Haldir SDK — Python client for the Haldir REST API.

Provides sync (HaldirClient) and async (HaldirAsyncClient) wrappers
for Gate, Vault, Watch, and Payments endpoints.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx


# ── Exceptions ──

class HaldirAPIError(Exception):
    """Base exception for all Haldir API errors."""

    def __init__(self, message: str, status_code: int = 0, body: dict | None = None):
        self.status_code = status_code
        self.body = body or {}
        super().__init__(message)


class HaldirAuthError(HaldirAPIError):
    """Raised on 401 — invalid or missing API key."""
    pass


class HaldirPermissionError(HaldirAPIError):
    """Raised on 403 — action not permitted (scope, budget, etc.)."""
    pass


class HaldirNotFoundError(HaldirAPIError):
    """Raised on 404 — resource not found."""
    pass


# ── Helpers ──

def _raise_for_status(response: httpx.Response) -> None:
    """Map HTTP error codes to typed exceptions."""
    if response.status_code < 400:
        return

    try:
        body = response.json()
    except Exception:
        body = {}

    message = body.get("error") or body.get("reason") or response.text

    if response.status_code == 401:
        raise HaldirAuthError(message, status_code=401, body=body)
    elif response.status_code == 403:
        raise HaldirPermissionError(message, status_code=403, body=body)
    elif response.status_code == 404:
        raise HaldirNotFoundError(message, status_code=404, body=body)
    else:
        raise HaldirAPIError(message, status_code=response.status_code, body=body)


# ── Sync Client ──

class HaldirClient:
    """Synchronous client for the Haldir API.

    Usage::

        h = HaldirClient(api_key="hld_xxx", base_url="https://haldir.xyz")
        session = h.create_session("my-agent", scopes=["read", "browse"])
        h.check_permission(session["session_id"], "read")
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://haldir.xyz",
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> HaldirClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        """Send a request and return parsed JSON, raising on errors."""
        resp = self._client.request(method, path, **kwargs)
        _raise_for_status(resp)
        return resp.json()  # type: ignore[no-any-return]

    # ── Gate ──

    def create_session(
        self,
        agent_id: str,
        scopes: Optional[list[str]] = None,
        ttl: int = 3600,
        spend_limit: Optional[float] = None,
    ) -> dict:
        """Create an agent session with the given scopes and spend limit.

        Returns a dict with session_id, agent_id, scopes, spend_limit, expires_at, ttl.
        """
        payload: dict[str, Any] = {"agent_id": agent_id, "ttl": ttl}
        if scopes is not None:
            payload["scopes"] = scopes
        if spend_limit is not None:
            payload["spend_limit"] = spend_limit
        return self._request("POST", "/v1/sessions", json=payload)

    def get_session(self, session_id: str) -> dict:
        """Retrieve session details including spend and validity status."""
        return self._request("GET", f"/v1/sessions/{session_id}")

    def revoke_session(self, session_id: str) -> dict:
        """Revoke an active session immediately."""
        return self._request("DELETE", f"/v1/sessions/{session_id}")

    def check_permission(self, session_id: str, scope: str) -> dict:
        """Check whether a session has a specific scope.

        Returns a dict with allowed (bool), session_id, and scope.
        """
        return self._request("POST", f"/v1/sessions/{session_id}/check", json={"scope": scope})

    # ── Vault ──

    def store_secret(
        self,
        name: str,
        value: str,
        scope_required: str = "read",
    ) -> dict:
        """Store an encrypted secret in the vault.

        Returns a dict with stored (bool) and name.
        """
        return self._request("POST", "/v1/secrets", json={
            "name": name,
            "value": value,
            "scope_required": scope_required,
        })

    def get_secret(
        self,
        name: str,
        session_id: Optional[str] = None,
    ) -> dict:
        """Retrieve a secret by name.

        If session_id is provided, the session's scopes are checked against
        the secret's required scope.

        Returns a dict with name and value.
        """
        headers = {}
        if session_id:
            headers["X-Session-ID"] = session_id
        return self._request("GET", f"/v1/secrets/{name}", headers=headers)

    def delete_secret(self, name: str) -> dict:
        """Delete a secret from the vault.

        Returns a dict with deleted (bool) and name.
        """
        return self._request("DELETE", f"/v1/secrets/{name}")

    def list_secrets(self) -> dict:
        """List all secret names in the vault.

        Returns a dict with secrets (list of names) and count.
        """
        return self._request("GET", "/v1/secrets")

    # ── Payments ──

    def authorize_payment(
        self,
        session_id: str,
        amount: float,
        currency: str = "USD",
        description: str = "",
    ) -> dict:
        """Authorize a payment against the session's spend limit.

        Returns a dict with authorized (bool), amount, remaining_budget, etc.
        Raises HaldirPermissionError if the budget is exceeded.
        """
        return self._request("POST", "/v1/payments/authorize", json={
            "session_id": session_id,
            "amount": amount,
            "currency": currency,
            "description": description,
        })

    # ── Watch ──

    def log_action(
        self,
        session_id: str,
        tool: str = "",
        action: str = "",
        cost_usd: float = 0.0,
        details: Optional[dict] = None,
    ) -> dict:
        """Log an auditable action tied to a session.

        Returns a dict with logged (bool), entry_id, flagged, flag_reason.
        """
        payload: dict[str, Any] = {
            "session_id": session_id,
            "tool": tool,
            "action": action,
            "cost_usd": cost_usd,
        }
        if details is not None:
            payload["details"] = details
        return self._request("POST", "/v1/audit", json=payload)

    def get_audit_trail(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool: Optional[str] = None,
        flagged_only: bool = False,
        limit: int = 100,
    ) -> dict:
        """Query the audit trail with optional filters.

        Returns a dict with count and entries list.
        """
        params: dict[str, Any] = {"limit": limit}
        if session_id:
            params["session_id"] = session_id
        if agent_id:
            params["agent_id"] = agent_id
        if tool:
            params["tool"] = tool
        if flagged_only:
            params["flagged"] = "true"
        return self._request("GET", "/v1/audit", params=params)

    def get_spend(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> dict:
        """Get spend summary, optionally filtered by session or agent.

        Returns a dict with total_usd, by_tool, etc.
        """
        params: dict[str, Any] = {}
        if session_id:
            params["session_id"] = session_id
        if agent_id:
            params["agent_id"] = agent_id
        return self._request("GET", "/v1/audit/spend", params=params)


# ── Async Client ──

class HaldirAsyncClient:
    """Asynchronous client for the Haldir API.

    Usage::

        async with HaldirAsyncClient(api_key="hld_xxx") as h:
            session = await h.create_session("my-agent", scopes=["read"])
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://haldir.xyz",
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )

    async def close(self) -> None:
        """Close the underlying async HTTP connection pool."""
        await self._client.aclose()

    async def __aenter__(self) -> HaldirAsyncClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        """Send an async request and return parsed JSON, raising on errors."""
        resp = await self._client.request(method, path, **kwargs)
        _raise_for_status(resp)
        return resp.json()  # type: ignore[no-any-return]

    # ── Gate ──

    async def create_session(
        self,
        agent_id: str,
        scopes: Optional[list[str]] = None,
        ttl: int = 3600,
        spend_limit: Optional[float] = None,
    ) -> dict:
        """Create an agent session with the given scopes and spend limit."""
        payload: dict[str, Any] = {"agent_id": agent_id, "ttl": ttl}
        if scopes is not None:
            payload["scopes"] = scopes
        if spend_limit is not None:
            payload["spend_limit"] = spend_limit
        return await self._request("POST", "/v1/sessions", json=payload)

    async def get_session(self, session_id: str) -> dict:
        """Retrieve session details including spend and validity status."""
        return await self._request("GET", f"/v1/sessions/{session_id}")

    async def revoke_session(self, session_id: str) -> dict:
        """Revoke an active session immediately."""
        return await self._request("DELETE", f"/v1/sessions/{session_id}")

    async def check_permission(self, session_id: str, scope: str) -> dict:
        """Check whether a session has a specific scope."""
        return await self._request("POST", f"/v1/sessions/{session_id}/check", json={"scope": scope})

    # ── Vault ──

    async def store_secret(
        self,
        name: str,
        value: str,
        scope_required: str = "read",
    ) -> dict:
        """Store an encrypted secret in the vault."""
        return await self._request("POST", "/v1/secrets", json={
            "name": name,
            "value": value,
            "scope_required": scope_required,
        })

    async def get_secret(
        self,
        name: str,
        session_id: Optional[str] = None,
    ) -> dict:
        """Retrieve a secret by name, optionally scoped to a session."""
        headers = {}
        if session_id:
            headers["X-Session-ID"] = session_id
        return await self._request("GET", f"/v1/secrets/{name}", headers=headers)

    async def delete_secret(self, name: str) -> dict:
        """Delete a secret from the vault."""
        return await self._request("DELETE", f"/v1/secrets/{name}")

    async def list_secrets(self) -> dict:
        """List all secret names in the vault."""
        return await self._request("GET", "/v1/secrets")

    # ── Payments ──

    async def authorize_payment(
        self,
        session_id: str,
        amount: float,
        currency: str = "USD",
        description: str = "",
    ) -> dict:
        """Authorize a payment against the session's spend limit."""
        return await self._request("POST", "/v1/payments/authorize", json={
            "session_id": session_id,
            "amount": amount,
            "currency": currency,
            "description": description,
        })

    # ── Watch ──

    async def log_action(
        self,
        session_id: str,
        tool: str = "",
        action: str = "",
        cost_usd: float = 0.0,
        details: Optional[dict] = None,
    ) -> dict:
        """Log an auditable action tied to a session."""
        payload: dict[str, Any] = {
            "session_id": session_id,
            "tool": tool,
            "action": action,
            "cost_usd": cost_usd,
        }
        if details is not None:
            payload["details"] = details
        return await self._request("POST", "/v1/audit", json=payload)

    async def get_audit_trail(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool: Optional[str] = None,
        flagged_only: bool = False,
        limit: int = 100,
    ) -> dict:
        """Query the audit trail with optional filters."""
        params: dict[str, Any] = {"limit": limit}
        if session_id:
            params["session_id"] = session_id
        if agent_id:
            params["agent_id"] = agent_id
        if tool:
            params["tool"] = tool
        if flagged_only:
            params["flagged"] = "true"
        return await self._request("GET", "/v1/audit", params=params)

    async def get_spend(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> dict:
        """Get spend summary, optionally filtered by session or agent."""
        params: dict[str, Any] = {}
        if session_id:
            params["session_id"] = session_id
        if agent_id:
            params["agent_id"] = agent_id
        return await self._request("GET", "/v1/audit/spend", params=params)
