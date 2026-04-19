"""
Haldir API-key scopes — granular per-key permissions.

Why scopes:

  - Procurement always asks: "can I create a read-only key for our SIEM
    ingest pipeline that can pull audit but can't mint sessions or
    rotate secrets?" Without scopes the answer is "no, every key has
    full power" and the deal stalls.
  - Operationally: a CI job that publishes audit logs should not be
    able to authorize payments. Least privilege at the key layer is
    the cheapest defense against a leaked CI token.
  - Stripe / GitHub / AWS all ship this. It's table stakes for any
    serious infra API.

── Vocabulary ─────────────────────────────────────────────────────────

Scopes are strings of the form `<resource>:<action>`. A few shortcuts:

  "*"               wildcard — every resource, every action. Default
                    on every existing key (back-compat) and on freshly
                    minted keys when no scopes are specified.
  "<resource>:*"    every action on this resource (e.g. "audit:*").
  "<resource>:read" read access on this resource.
  "<resource>:write" write access — also implies "read" for the same
                    resource (write-implies-read by convention).
  "<resource>:<verb>" custom verb (rarely needed; reserved).

Resources currently in the vocabulary:

  sessions    /v1/sessions
  vault       /v1/secrets
  audit       /v1/audit, /v1/audit/export, /v1/audit/verify
  payments    /v1/payments
  webhooks    /v1/webhooks
  proxy       /v1/proxy
  approvals   /v1/approvals
  admin       /v1/admin/*

── Matching algorithm ────────────────────────────────────────────────

A key with `granted_scopes = ["audit:read", "sessions:read"]` matches
required scope `"audit:read"` because the exact string is present.

Wildcard expansion:
  granted "*"            → matches anything
  granted "audit:*"      → matches "audit:read", "audit:write", etc.
  granted "audit:write"  → matches "audit:read" too (write-implies-read)

The matcher is pure-function over two string lists; no DB calls inside
the hot path. Used by the @require_scope decorator at request time.
"""

from __future__ import annotations

import json
from functools import wraps
from typing import Any, Callable, Iterable

from flask import request, jsonify, g

from haldir_logging import get_logger


log = get_logger("haldir.scopes")

# Stable resource list. New endpoints either map to one of these or
# this list grows with a documented contract. Not user-extensible —
# we own this vocabulary.
KNOWN_RESOURCES: frozenset[str] = frozenset({
    "sessions", "vault", "audit", "payments",
    "webhooks", "proxy", "approvals", "admin",
})

KNOWN_ACTIONS: frozenset[str] = frozenset({"read", "write"})

# The default for every key minted before this migration ran, plus
# every key minted today that doesn't pass `scopes` explicitly.
WILDCARD: str = "*"

# Explicit "no scopes" — empty list means the key can do nothing.
# Reject this at creation time; treat as wildcard at read time
# (defense in depth against accidentally-locked-out admin keys).
EMPTY_SCOPES: list[str] = []


# ── Parsing + validation ─────────────────────────────────────────────

def parse(value: Any) -> list[str]:
    """Normalize whatever the DB / request body gave us into a list of
    scope strings. Tolerant on input — strings get split on commas,
    None becomes wildcard, JSON strings are decoded. Stripping is
    aggressive so users can paste with whitespace."""
    if value is None:
        return [WILDCARD]
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return [WILDCARD]
        # JSON array form: '["audit:read","sessions:read"]'
        if s.startswith("["):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed if str(x).strip()]
            except json.JSONDecodeError:
                pass
        # Comma-separated form: "audit:read,sessions:read"
        return [p.strip() for p in s.split(",") if p.strip()]
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return [WILDCARD]


class ScopeValidationError(ValueError):
    """Raised when a scope string isn't well-formed at creation time."""


def validate(scopes: Iterable[str]) -> list[str]:
    """Reject malformed scope strings before they hit the DB. Anchors
    the vocabulary so a typo like 'aduit:read' is a 400, not a silent
    permanent denial."""
    cleaned: list[str] = []
    for s in scopes:
        s = s.strip()
        if not s:
            continue
        if s == WILDCARD:
            cleaned.append(s)
            continue
        if ":" not in s:
            raise ScopeValidationError(
                f"scope {s!r} must be '<resource>:<action>' or '*'",
            )
        resource, action = s.split(":", 1)
        if resource not in KNOWN_RESOURCES:
            raise ScopeValidationError(
                f"unknown resource {resource!r} in scope {s!r}; "
                f"valid resources: {sorted(KNOWN_RESOURCES)}",
            )
        if action != "*" and action not in KNOWN_ACTIONS:
            raise ScopeValidationError(
                f"unknown action {action!r} in scope {s!r}; "
                f"valid actions: {sorted(KNOWN_ACTIONS) + ['*']}",
            )
        cleaned.append(s)
    if not cleaned:
        raise ScopeValidationError("scope list is empty; pass [\"*\"] for wildcard")
    return cleaned


def serialize(scopes: list[str]) -> str:
    """Canonical JSON form for the DB column. Sorted for stable
    comparison in tests + audit diffs."""
    return json.dumps(sorted(set(scopes)), separators=(",", ":"))


# ── Matching ─────────────────────────────────────────────────────────

def authorizes(granted: list[str], required: str) -> bool:
    """Does a key with `granted` scopes authorize a `required` scope?

    Order of checks:
      1. `*` in granted → always allowed.
      2. `required` literal in granted.
      3. resource-wildcard `<resource>:*` in granted, where resource
         matches the required scope's resource half.
      4. write-implies-read: if required is `<r>:read` and granted has
         `<r>:write`, allow.
    """
    if WILDCARD in granted:
        return True
    if required in granted:
        return True
    if ":" not in required:
        return False
    res, action = required.split(":", 1)
    if f"{res}:*" in granted:
        return True
    if action == "read" and f"{res}:write" in granted:
        return True
    return False


# ── Decorator ────────────────────────────────────────────────────────

def require_scope(required: str) -> Callable[[Callable], Callable]:
    """Decorator that returns 403 unless the authed key carries the
    required scope. Stacks UNDER @require_api_key (which loads the
    granted scopes onto request.api_key_scopes).

    Usage:
        @app.route("/v1/audit", methods=["GET"])
        @require_api_key
        @require_scope("audit:read")
        def get_audit_trail(): ...
    """

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            granted = getattr(request, "api_key_scopes", None)
            # Missing scopes context = the decorator was used outside
            # an authed path. Fail closed.
            if granted is None:
                return jsonify({
                    "error":      "scope check requires authenticated key",
                    "code":       "scope_check_no_auth",
                    "request_id": getattr(g, "request_id", ""),
                }), 401
            if not authorizes(granted, required):
                return jsonify({
                    "error":      f"key lacks required scope {required!r}",
                    "code":       "insufficient_scope",
                    "required":   required,
                    "granted":    granted,
                    "request_id": getattr(g, "request_id", ""),
                }), 403
            return fn(*args, **kwargs)

        # Stash the requirement on the wrapper so the OpenAPI generator
        # (and operators introspecting the route) can read it back.
        wrapper.__haldir_required_scope__ = required  # type: ignore[attr-defined]
        return wrapper

    return decorator
