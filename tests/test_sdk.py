"""
Haldir SDK tests — exercises the SDK against the Flask test client.

Uses httpx's custom transport to route SDK requests through Flask's
WSGI app instead of making real HTTP calls.

Run:
    cd ~/Desktop/Haldir && python -m pytest tests/test_sdk.py -v
"""

import os
import sys
import asyncio
import pytest

# Set up paths before any Haldir imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# This module used to point HALDIR_DB_PATH at a private database here, at
# import time, and delete it in teardown_module(). Both were leftovers from
# before the fixtures below moved onto conftest's shared bootstrap key, and
# both were actively harmful: pytest imports every test module before running
# any test, so the env var pinned api.DB_PATH for every module imported after
# this one, and the teardown then deleted the database out from under them.
# The visible symptom was any module collected after this one failing with
# "no such table: api_keys". The fixtures below say why the wipe had to go —
# it invalidates conftest.bootstrap_key for the whole session.

import httpx
from api import app as flask_app
from sdk.client import (
    HaldirClient,
    HaldirAsyncClient,
    HaldirAuthError,
    HaldirPermissionError,
    HaldirNotFoundError,
)


# ── Transport adapter: route httpx requests through Flask WSGI ──

class FlaskTransport(httpx.BaseTransport):
    """HTTPX transport that dispatches to a Flask test client."""

    def __init__(self, flask_app):
        self._client = flask_app.test_client()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # Build path with query string
        path = request.url.raw_path.decode("ascii")

        # Merge SDK headers with per-request headers
        headers = dict(request.headers)

        body = request.content if request.content else None

        resp = self._client.open(
            path,
            method=request.method,
            headers=headers,
            data=body,
            content_type=headers.get("content-type", "application/json"),
        )

        return httpx.Response(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            content=resp.data,
        )


class AsyncFlaskTransport(httpx.AsyncBaseTransport):
    """Async wrapper around the same Flask test client (runs sync under the hood)."""

    def __init__(self, flask_app):
        self._sync = FlaskTransport(flask_app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self._sync.handle_request(request)


# ── Fixtures ──

@pytest.fixture(autouse=True)
def _lift_agent_cap(monkeypatch):
    """The SDK suite creates ~20 agents across tests. Free tier caps
    agents at 1; lift it so every test gets a fresh session without
    hitting the tier limiter. Same pattern used by test_admin.py /
    test_compliance_score.py / test_audit_tree.py."""
    import copy
    import api
    patched = copy.deepcopy(api.TIER_LIMITS)
    patched["free"]["agents"] = 999
    monkeypatch.setattr(api, "TIER_LIMITS", patched)


@pytest.fixture(scope="module")
def api_key(bootstrap_key):
    """Mint a fresh API key for this module using conftest's session-
    scoped bootstrap_key as the admin credential.

    Piggybacking on conftest avoids wiping api_keys — a wipe would
    invalidate conftest.bootstrap_key and break every other test module
    that depends on it."""
    client = flask_app.test_client()
    r = client.post(
        "/v1/keys",
        json={"name": "sdk-test", "tier": "pro"},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 201, f"key mint failed: {r.status_code} {r.data!r}"
    return r.json["key"]


@pytest.fixture(scope="module")
def haldir(api_key):
    """Build a HaldirClient wired to the Flask test app."""
    transport = FlaskTransport(flask_app)
    h = HaldirClient.__new__(HaldirClient)
    h.base_url = "http://localhost"
    h._client = httpx.Client(
        base_url="http://localhost",
        headers={"Authorization": f"Bearer {api_key}"},
        transport=transport,
        timeout=30.0,
    )
    yield h
    h.close()



# ── Gate tests ──

class TestGate:
    def test_create_session(self, haldir):
        session = haldir.create_session("test-agent", scopes=["read", "browse", "spend"], spend_limit=100.0)
        assert "session_id" in session
        assert session["agent_id"] == "test-agent"
        assert "read" in session["scopes"]
        assert session["spend_limit"] == 100.0

    def test_get_session(self, haldir):
        session = haldir.create_session("get-agent", scopes=["read"])
        info = haldir.get_session(session["session_id"])
        assert info["session_id"] == session["session_id"]
        assert info["is_valid"] is True

    def test_check_permission_allowed(self, haldir):
        session = haldir.create_session("perm-agent", scopes=["read", "write"])
        result = haldir.check_permission(session["session_id"], "read")
        assert result["allowed"] is True

    def test_check_permission_denied(self, haldir):
        session = haldir.create_session("perm-agent2", scopes=["read"])
        result = haldir.check_permission(session["session_id"], "delete")
        assert result["allowed"] is False

    def test_revoke_session(self, haldir):
        session = haldir.create_session("revoke-agent", scopes=["read"])
        result = haldir.revoke_session(session["session_id"])
        assert result["revoked"] is True

    def test_get_revoked_session_404(self, haldir):
        session = haldir.create_session("gone-agent", scopes=["read"])
        haldir.revoke_session(session["session_id"])
        with pytest.raises(HaldirNotFoundError):
            haldir.get_session(session["session_id"])

    def test_revoke_nonexistent_session_404(self, haldir):
        with pytest.raises(HaldirNotFoundError):
            haldir.revoke_session("nonexistent-session-id")


# ── Vault tests ──

class TestVault:
    def test_store_and_get_secret(self, haldir):
        haldir.store_secret("test_key", "sk_test_abc123")
        session = haldir.create_session("secret-agent", scopes=["read"])
        result = haldir.get_secret("test_key", session_id=session["session_id"])
        assert result["value"] == "sk_test_abc123"

    def test_get_secret_with_session(self, haldir):
        haldir.store_secret("scoped_key", "secret_value", scope_required="read")
        session = haldir.create_session("vault-agent", scopes=["read"])
        result = haldir.get_secret("scoped_key", session_id=session["session_id"])
        assert result["value"] == "secret_value"

    def test_list_secrets(self, haldir):
        haldir.store_secret("list_key", "value")
        result = haldir.list_secrets()
        assert "list_key" in result["secrets"]
        assert result["count"] > 0

    def test_delete_secret(self, haldir):
        haldir.store_secret("del_key", "value")
        result = haldir.delete_secret("del_key")
        assert result["deleted"] is True

    def test_get_missing_secret_404(self, haldir):
        session = haldir.create_session("secret-agent", scopes=["read"])
        with pytest.raises(HaldirNotFoundError):
            haldir.get_secret("nonexistent_secret", session_id=session["session_id"])

    def test_delete_missing_secret_404(self, haldir):
        with pytest.raises(HaldirNotFoundError):
            haldir.delete_secret("nonexistent_secret")


# ── Payments tests ──

class TestPayments:
    def test_authorize_payment(self, haldir):
        session = haldir.create_session("pay-agent", scopes=["read", "spend"], spend_limit=100.0)
        result = haldir.authorize_payment(session["session_id"], 29.99, description="test charge")
        assert result["authorized"] is True
        assert result["amount"] == 29.99

    def test_overspend_blocked(self, haldir):
        session = haldir.create_session("broke-agent", scopes=["read", "spend"], spend_limit=10.0)
        with pytest.raises(HaldirPermissionError):
            haldir.authorize_payment(session["session_id"], 50.00)


# ── Watch tests ──

class TestWatch:
    def test_log_action(self, haldir):
        session = haldir.create_session("audit-agent", scopes=["read"])
        result = haldir.log_action(session["session_id"], tool="stripe", action="charge", cost_usd=9.99)
        assert result["logged"] is True
        assert "entry_id" in result

    def test_get_audit_trail(self, haldir):
        session = haldir.create_session("trail-agent", scopes=["read"])
        haldir.log_action(session["session_id"], tool="github", action="push")
        trail = haldir.get_audit_trail(agent_id="trail-agent")
        assert trail["count"] >= 1
        assert trail["entries"][0]["tool"] == "github"

    def test_get_spend(self, haldir):
        session = haldir.create_session("spend-agent", scopes=["read"])
        haldir.log_action(session["session_id"], tool="openai", action="completion", cost_usd=0.03)
        spend = haldir.get_spend(agent_id="spend-agent")
        assert spend["total_usd"] >= 0.03


# ── Auth error tests ──

class TestAuthErrors:
    def test_bad_api_key_raises_auth_error(self):
        transport = FlaskTransport(flask_app)
        bad_client = HaldirClient.__new__(HaldirClient)
        bad_client.base_url = "http://localhost"
        bad_client._client = httpx.Client(
            base_url="http://localhost",
            headers={"Authorization": "Bearer bad_key_xxx"},
            transport=transport,
            timeout=30.0,
        )
        with pytest.raises(HaldirAuthError) as exc_info:
            bad_client.create_session("agent")
        assert exc_info.value.status_code == 401
        bad_client.close()

    def test_no_api_key_raises_auth_error(self):
        transport = FlaskTransport(flask_app)
        no_key_client = HaldirClient.__new__(HaldirClient)
        no_key_client.base_url = "http://localhost"
        no_key_client._client = httpx.Client(
            base_url="http://localhost",
            headers={},
            transport=transport,
            timeout=30.0,
        )
        with pytest.raises(HaldirAuthError):
            no_key_client.list_secrets()
        no_key_client.close()


# ── Async client tests ──

class TestAsyncClient:
    def _make_async_client(self, api_key):
        transport = AsyncFlaskTransport(flask_app)
        h = HaldirAsyncClient.__new__(HaldirAsyncClient)
        h.base_url = "http://localhost"
        h._client = httpx.AsyncClient(
            base_url="http://localhost",
            headers={"Authorization": f"Bearer {api_key}"},
            transport=transport,
            timeout=30.0,
        )
        return h

    def test_create_and_revoke_session(self, api_key):
        async def run():
            h = self._make_async_client(api_key)
            session = await h.create_session("async-agent", scopes=["read", "write"])
            assert "session_id" in session
            result = await h.revoke_session(session["session_id"])
            assert result["revoked"] is True
            await h.close()
        asyncio.run(run())

    def test_vault_roundtrip(self, api_key):
        async def run():
            h = self._make_async_client(api_key)
            await h.store_secret("async_key", "async_value")
            session = await h.create_session("async-agent", scopes=["read"])
            result = await h.get_secret("async_key", session_id=session["session_id"])
            assert result["value"] == "async_value"
            await h.delete_secret("async_key")
            await h.close()
        asyncio.run(run())

    def test_log_and_query(self, api_key):
        async def run():
            h = self._make_async_client(api_key)
            session = await h.create_session("async-watch", scopes=["read"])
            await h.log_action(session["session_id"], tool="test", action="ping")
            trail = await h.get_audit_trail(agent_id="async-watch")
            assert trail["count"] >= 1
            await h.close()
        asyncio.run(run())


# ── The payload the SDK actually sends ───────────────────────────────

def _capturing_sync_client():
    """An SDK client whose transport records each request body.

    Built on a real httpx transport rather than by replacing `_request`, so
    the test observes the payload *after serialization* — which is where
    `"ttl": null` actually went out on the wire.
    """
    import json as _json

    import httpx

    from sdk.client import HaldirClient

    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(_json.loads(request.content) if request.content else {})
        return httpx.Response(200, json={"session_id": "ses_probe"})

    h = HaldirClient(api_key="hld_probe", base_url="http://probe.test")
    h._client = httpx.Client(
        transport=httpx.MockTransport(handler), base_url="http://probe.test",
    )
    return h, seen


def test_create_session_omits_ttl_rather_than_sending_null() -> None:
    """An omitted optional field must be absent from the body, not null.

    `ttl` was the one optional field the SDK did not guard, so it always went
    out — as `null` when the caller had no opinion. The server rejects an
    explicit null ("expected int, got NoneType") while reading an absent key
    as "use the default", so the two spellings of "no preference" behaved
    differently and one of them was a 400.

    That was not theoretical: `crewai-haldir` and `autogen-haldir` both
    default `ttl=None` and forward it, so every documented quickstart for
    those two integrations failed on its first call. Their tests mock
    `HaldirClient`, so nothing had ever looked at a real payload.
    """
    h, seen = _capturing_sync_client()

    # The defect itself: an explicit None reached the wire as JSON null. This
    # is the assertion that fails on the unfixed SDK — with "sent as None".
    h.create_session("agent", ttl=None)
    assert "ttl" not in seen[0], (
        f"ttl=None was sent as {seen[0].get('ttl')!r}; it must be absent so "
        f"the server applies its default rather than rejecting the null"
    )

    # An explicit value still travels.
    h.create_session("agent", ttl=120)
    assert seen[1]["ttl"] == 120

    # And the other optional fields keep their existing behaviour.
    h.create_session("agent", scopes=["read"], spend_limit=5.0)
    assert seen[2]["scopes"] == ["read"]
    assert seen[2]["spend_limit"] == 5.0


def test_the_payload_the_sdk_builds_is_one_the_api_accepts(
    haldir_client, bootstrap_key
) -> None:
    """The two halves together.

    The test above pins what the SDK sends; this sends that exact body to the
    real route, so the pair fails if either side moves. Uses the shared
    fixtures rather than minting a key — `POST /v1/keys` is not reliably
    available on the long-lived test database, and a guard that skips is not
    a guard.
    """
    h, seen = _capturing_sync_client()
    h.create_session("sdk-payload-probe", ttl=None)
    assert "ttl" not in seen[0]

    r = haldir_client.post(
        "/v1/sessions", json=seen[0],
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 201, (
        f"the SDK's own payload was rejected by the API: {r.status_code} {r.data}"
    )


# No teardown: this module shares conftest's session database, so there is
# nothing of its own to clean up. See the note at the top of the file.
