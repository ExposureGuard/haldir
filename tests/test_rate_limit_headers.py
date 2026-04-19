"""
Tests for the rate-limit header surface.

Stripe, GitHub, and every mature API ship a precise rate-limit header
contract: clients shouldn't have to parse a JSON error body to know how
long to back off. This suite locks in the shape:

  On every authed response:
    X-RateLimit-Limit         hourly ceiling
    X-RateLimit-Remaining     hourly budget left
    X-RateLimit-Used          requests consumed this window
    X-RateLimit-Reset         unix epoch when the window rolls
    X-RateLimit-Reset-After   seconds until that happens
    X-RateLimit-Resource      which bucket ("hourly" | "monthly")

  On monthly-quota-aware responses:
    X-RateLimit-Monthly-Limit
    X-RateLimit-Monthly-Remaining
    X-RateLimit-Monthly-Used
    X-RateLimit-Monthly-Reset
    X-RateLimit-Monthly-Reset-After

  On any 429:
    Retry-After               RFC 7231 seconds-until-retry

Run: python -m pytest tests/test_rate_limit_headers.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# `fresh_counter` lives in conftest.py — shared across the suite.


# ── Happy-path headers on a 200 response ──────────────────────────────

def test_success_response_has_hourly_headers(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(
        "/v1/audit?limit=1",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    for h in (
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Used",
        "X-RateLimit-Reset",
        "X-RateLimit-Reset-After",
        "X-RateLimit-Resource",
    ):
        assert h in r.headers, f"missing {h} on 200"
    # Used is the count consumed so far — always >= 1 after this call.
    assert int(r.headers["X-RateLimit-Used"]) >= 1
    # Remaining + Used should never exceed Limit.
    assert int(r.headers["X-RateLimit-Used"]) + int(r.headers["X-RateLimit-Remaining"]) <= int(r.headers["X-RateLimit-Limit"]) + 1
    assert r.headers["X-RateLimit-Resource"] == "hourly"


def test_reset_after_is_positive_seconds(haldir_client, bootstrap_key) -> None:
    """Reset-After counts down; immediately after a fresh window it
    should be roughly the full window length, never negative."""
    r = haldir_client.get(
        "/healthz",  # hits pre-request rate-limit hook only if it's /v1/*
    )
    # Health check isn't behind the rate limiter, so no headers.
    assert "X-RateLimit-Reset-After" not in r.headers

    r = haldir_client.get(
        "/v1/audit?limit=1",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    ra = int(r.headers["X-RateLimit-Reset-After"])
    assert 0 <= ra <= 3600


# ── 429 response headers ──────────────────────────────────────────────

def test_429_emits_retry_after(monkeypatch, haldir_client, bootstrap_key, fresh_counter) -> None:
    """Drive the hourly counter past its ceiling and assert the 429
    carries Retry-After + full X-RateLimit-* surface."""
    import api
    # Temporarily squeeze the free-tier limit so we can exhaust it
    # quickly without hammering the DB 100 times.
    # /v1/keys hardcodes tier=free on creation (only Stripe webhooks
    # upgrade), so the bootstrap key lives on the free-tier limit.
    monkeypatch.setitem(api.RATE_LIMITS, "free", 1)

    # First call consumes the budget (count=1 == limit=1, still under).
    r1 = haldir_client.get(
        "/v1/audit?limit=1",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r1.status_code == 200
    # Second call trips the limit → 429.
    r2 = haldir_client.get(
        "/v1/audit?limit=1",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r2.status_code == 429
    body = r2.get_json()
    assert body["code"] == "rate_limit_exceeded"

    # Header surface.
    assert "Retry-After" in r2.headers
    retry = int(r2.headers["Retry-After"])
    assert retry >= 1
    # The 429 must also carry the same X-RateLimit-* breadcrumbs so
    # clients don't have to re-probe to figure out when the window
    # resets.
    for h in (
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "X-RateLimit-Reset-After",
        "X-RateLimit-Resource",
    ):
        assert h in r2.headers, f"missing {h} on 429"
    assert r2.headers["X-RateLimit-Resource"] == "hourly"
    # Remaining on the overflow response must report 0 (not negative).
    assert int(r2.headers["X-RateLimit-Remaining"]) == 0


def test_429_retry_after_matches_reset_after(monkeypatch, haldir_client, bootstrap_key, fresh_counter) -> None:
    """Retry-After and X-RateLimit-Reset-After should agree — they're
    two spellings of the same number."""
    import api
    # /v1/keys hardcodes tier=free on creation (only Stripe webhooks
    # upgrade), so the bootstrap key lives on the free-tier limit.
    monkeypatch.setitem(api.RATE_LIMITS, "free", 1)

    haldir_client.get(
        "/v1/audit?limit=1",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    r = haldir_client.get(
        "/v1/audit?limit=1",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 429
    retry = int(r.headers["Retry-After"])
    reset_after = int(r.headers["X-RateLimit-Reset-After"])
    # Allow a 1-second drift — the two reads of `time.time()` happen
    # close together but aren't the same call.
    assert abs(retry - reset_after) <= 1


def test_body_retry_after_matches_header(monkeypatch, haldir_client, bootstrap_key, fresh_counter) -> None:
    """Historic clients parse the JSON body; modern ones read the
    header. Both should carry the same number so they don't diverge."""
    import api
    # /v1/keys hardcodes tier=free on creation (only Stripe webhooks
    # upgrade), so the bootstrap key lives on the free-tier limit.
    monkeypatch.setitem(api.RATE_LIMITS, "free", 1)

    haldir_client.get(
        "/v1/audit?limit=1",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    r = haldir_client.get(
        "/v1/audit?limit=1",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 429
    body = r.get_json()
    header = int(r.headers["Retry-After"])
    assert abs(int(body["retry_after"]) - header) <= 1


# ── Monthly quota dimension ───────────────────────────────────────────

def test_monthly_headers_present_when_tenant_resolved(haldir_client, bootstrap_key) -> None:
    """Once the authed call has a resolved tenant, the monthly-quota
    headers should also ship — clients on metered plans need visibility
    into both dimensions simultaneously."""
    r = haldir_client.get(
        "/v1/audit?limit=1",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    # bootstrap_key lives on the free tier (/v1/keys always writes
    # tier=free; only Stripe webhooks upgrade). Free-tier TIER_LIMITS
    # has a finite actions_per_month, so the monthly headers must
    # appear whenever a tenant is resolved.
    for h in (
        "X-RateLimit-Monthly-Limit",
        "X-RateLimit-Monthly-Remaining",
        "X-RateLimit-Monthly-Used",
        "X-RateLimit-Monthly-Reset",
        "X-RateLimit-Monthly-Reset-After",
    ):
        assert h in r.headers, f"missing monthly header {h}"
    assert int(r.headers["X-RateLimit-Monthly-Limit"]) > 0


# ── Resource tagging ──────────────────────────────────────────────────

def test_resource_header_is_hourly_by_default(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(
        "/v1/audit?limit=1",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.headers["X-RateLimit-Resource"] == "hourly"
