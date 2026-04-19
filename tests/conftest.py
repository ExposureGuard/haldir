"""
Shared pytest fixtures.

Haldir's API module (api.py) reads HALDIR_DB_PATH at import time and
pins Gate/Vault/Watch/Proxy to that path. Reloading api per test
module doesn't work cleanly because handlers dispatch through
module-level globals — reload rebinds them but any test_client
built against a prior import then hits the new globals.

The clean fix is a session-scoped shared DB + a bootstrap fixture
that both `test_api.py` and `test_middleware.py` (etc.) can opt into.

Test modules that explicitly override HALDIR_DB_PATH before importing
api (legacy pattern) are still supported — `setdefault` means our
shared path only applies if they haven't set their own.
"""

from __future__ import annotations

import os
import sys
import sqlite3

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="session")
def haldir_client():
    """A Flask test_client for the shared api module, guaranteed to have
    no API keys when first yielded (so bootstrap flows work)."""
    import api

    # Wipe keys on first use so the first caller can bootstrap.
    conn = sqlite3.connect(api.DB_PATH)
    conn.execute("DELETE FROM api_keys")
    conn.commit()
    conn.close()
    return api.app.test_client()


@pytest.fixture(scope="session")
def bootstrap_key(haldir_client):
    """A valid API key for tests that need auth. Bootstrapped once per
    session; test modules can depend on this instead of racing each
    other to call /v1/keys first."""
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "pytest-bootstrap", "tier": "pro"},
    )
    assert r.status_code == 201, f"bootstrap failed: {r.status_code} {r.data!r}"
    return r.get_json()["key"]


@pytest.fixture
def fresh_counter(bootstrap_key):
    """Reset the in-memory rate-limit counter for the bootstrap key
    so a test starts with count=0. Otherwise the cumulative request
    volume from the rest of the suite (300+ tests, many making
    multiple authed calls each) burns through the free-tier hourly
    quota before later tests run.

    Opt-in: only tests that depend on a clean rate-limit window need
    this. Other tests run unaffected."""
    import api
    import hashlib
    key_hash = hashlib.sha256(bootstrap_key.encode()).hexdigest()
    api._rate_limits.pop(key_hash, None)
    yield
    api._rate_limits.pop(key_hash, None)
