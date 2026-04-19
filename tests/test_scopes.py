"""
Tests for haldir_scopes — the scope vocabulary, matcher, decorator,
and end-to-end enforcement on representative endpoints.

Scope:
  - parse() normalizes string / list / JSON / None
  - validate() rejects unknown resources/actions and empty lists
  - authorizes() honors wildcard, resource-wildcard, write-implies-read
  - serialize() is canonical (sorted, deduped)
  - POST /v1/keys accepts scopes; bad scopes 400
  - Wildcard key (back-compat) works on every endpoint
  - Read-only key reads but 403s on write
  - Narrow key blocks unrelated resources

Run: python -m pytest tests/test_scopes.py -v
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_scopes  # noqa: E402
from haldir_scopes import (  # noqa: E402
    WILDCARD,
    ScopeValidationError,
    authorizes,
    parse,
    serialize,
    validate,
)


# ── parse() ──────────────────────────────────────────────────────────

def test_parse_none_yields_wildcard() -> None:
    assert parse(None) == [WILDCARD]


def test_parse_empty_string_yields_wildcard() -> None:
    assert parse("") == [WILDCARD]
    assert parse("   ") == [WILDCARD]


def test_parse_comma_separated_string() -> None:
    assert parse("audit:read, sessions:read") == ["audit:read", "sessions:read"]


def test_parse_json_array_string() -> None:
    assert parse('["audit:read","vault:write"]') == ["audit:read", "vault:write"]


def test_parse_python_list() -> None:
    assert parse(["audit:read", " sessions:read "]) == ["audit:read", "sessions:read"]


def test_parse_drops_empty_entries() -> None:
    assert parse(["audit:read", "", "  "]) == ["audit:read"]


# ── validate() ───────────────────────────────────────────────────────

def test_validate_accepts_wildcard() -> None:
    assert validate([WILDCARD]) == [WILDCARD]


def test_validate_accepts_resource_wildcard() -> None:
    assert validate(["audit:*"]) == ["audit:*"]


def test_validate_accepts_known_resource_action() -> None:
    assert validate(["audit:read", "sessions:write"]) == \
        ["audit:read", "sessions:write"]


def test_validate_rejects_unknown_resource() -> None:
    with pytest.raises(ScopeValidationError, match="unknown resource"):
        validate(["aduit:read"])  # typo


def test_validate_rejects_unknown_action() -> None:
    with pytest.raises(ScopeValidationError, match="unknown action"):
        validate(["audit:reed"])


def test_validate_rejects_missing_colon() -> None:
    with pytest.raises(ScopeValidationError, match="must be"):
        validate(["audit"])


def test_validate_rejects_empty_list() -> None:
    with pytest.raises(ScopeValidationError, match="empty"):
        validate([])


# ── serialize() ──────────────────────────────────────────────────────

def test_serialize_is_sorted_and_deduped() -> None:
    s = serialize(["sessions:read", "audit:read", "audit:read"])
    parsed = json.loads(s)
    assert parsed == ["audit:read", "sessions:read"]


# ── authorizes() ─────────────────────────────────────────────────────

def test_wildcard_authorizes_anything() -> None:
    assert authorizes([WILDCARD], "audit:write")
    assert authorizes([WILDCARD], "vault:read")
    assert authorizes([WILDCARD], "anything:goes")


def test_exact_match_authorizes() -> None:
    assert authorizes(["audit:read"], "audit:read")


def test_exact_mismatch_denies() -> None:
    assert not authorizes(["audit:read"], "audit:write")
    assert not authorizes(["audit:read"], "vault:read")


def test_resource_wildcard() -> None:
    assert authorizes(["audit:*"], "audit:read")
    assert authorizes(["audit:*"], "audit:write")
    assert not authorizes(["audit:*"], "vault:read")


def test_write_implies_read() -> None:
    """Granting write should also grant read on the same resource —
    matches the ergonomic expectation every API consumer has."""
    assert authorizes(["audit:write"], "audit:read")
    # Reverse is NOT true.
    assert not authorizes(["audit:read"], "audit:write")


# ── End-to-end via /v1/keys + scope-gated endpoint ───────────────────

def _mint_key_with_scopes(client, scopes: list[str]) -> str:
    r = client.post("/v1/keys", json={"name": "scoped", "scopes": scopes})
    assert r.status_code == 201, r.data
    return r.get_json()["key"]


def test_keys_endpoint_accepts_scopes(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "siem-ingest", "scopes": ["audit:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 201
    body = r.get_json()
    assert body["scopes"] == ["audit:read"]
    assert body["key"].startswith("hld_")


def test_keys_endpoint_rejects_invalid_scope(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "bad", "scopes": ["aduit:read"]},  # typo
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400
    assert r.get_json()["code"] == "invalid_scope"


def test_keys_endpoint_default_is_wildcard(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "default-perms"},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 201
    assert r.get_json()["scopes"] == ["*"]


def test_wildcard_key_can_hit_every_resource(haldir_client, bootstrap_key) -> None:
    """Back-compat sanity: bootstrap_key has scopes ['*'] (created
    before any narrowing); should still pass scope checks on
    audit + admin + sessions + secrets."""
    h = {"Authorization": f"Bearer {bootstrap_key}"}
    assert haldir_client.get("/v1/audit?limit=1", headers=h).status_code == 200
    assert haldir_client.get("/v1/admin/overview", headers=h).status_code == 200
    assert haldir_client.get("/v1/secrets", headers=h).status_code == 200


def test_read_only_audit_key_can_read_but_not_write(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "siem", "scopes": ["audit:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    siem_key = r.get_json()["key"]
    h = {"Authorization": f"Bearer {siem_key}"}

    # Read: 200.
    assert haldir_client.get("/v1/audit?limit=1", headers=h).status_code == 200
    # Write: 403 with insufficient_scope code.
    r2 = haldir_client.post(
        "/v1/audit",
        json={"session_id": "ses_x", "tool": "x", "action": "y"},
        headers=h,
    )
    assert r2.status_code == 403
    assert r2.get_json()["code"] == "insufficient_scope"
    assert r2.get_json()["required"] == "audit:write"


def test_read_only_audit_key_blocked_from_other_resources(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "narrow", "scopes": ["audit:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    narrow_key = r.get_json()["key"]
    h = {"Authorization": f"Bearer {narrow_key}"}
    # admin:read missing.
    assert haldir_client.get("/v1/admin/overview", headers=h).status_code == 403
    # vault:read missing.
    assert haldir_client.get("/v1/secrets", headers=h).status_code == 403


def test_resource_wildcard_key(haldir_client, bootstrap_key) -> None:
    """A key with `audit:*` should pass both audit:read and audit:write."""
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "audit-wide", "scopes": ["audit:*"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    k = r.get_json()["key"]
    h = {"Authorization": f"Bearer {k}"}
    assert haldir_client.get("/v1/audit?limit=1", headers=h).status_code == 200
    # Audit write requires a valid session — we don't have one, but the
    # 401/400 we get back must NOT be a 403/insufficient_scope.
    r2 = haldir_client.post(
        "/v1/audit",
        json={"session_id": "ses_x", "tool": "x", "action": "y"},
        headers=h,
    )
    assert r2.status_code != 403
