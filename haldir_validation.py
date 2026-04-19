"""
Haldir request validation.

Dependency-free `@validate_body` decorator that replaces the scattered
`data = request.json or {}` + `data.get("x", default)` + defensive
`isinstance` checks peppered through Flask handlers.

    @validate_body({
        "agent_id":     {"type": str,   "required": True, "maxlen": 128},
        "scopes":       {"type": list,  "default": []},
        "ttl":          {"type": int,   "default": 3600, "min": 1, "max": 86400},
        "spend_limit":  {"type": float, "default": 0.0,  "min": 0},
        "mode":         {"type": str,   "default": "normal",
                         "choices": ["normal", "strict", "audit_only"]},
    })
    def create_session():
        data = request.validated  # fully typed + defaulted
        ...

On violation: returns a structured 400 with the same envelope as the
rest of the API (code, error, request_id, plus `field` and `reason`).
Missing required field, wrong type, out-of-range number, bad enum,
over-length string — all caught before the handler body runs.

Design notes:

  - Types are ordinary Python builtins (str, int, float, bool, list,
    dict) so the schema reads like documentation and doesn't require a
    library import. Coercion is deliberately narrow — e.g. {"type": int}
    won't silently accept "42" because that masks client bugs.

  - Defaults are applied only when the caller omitted the field; an
    explicit `None` passes through and is rejected by the type check so
    clients can't sneak null into non-nullable fields.

  - The decorator attaches the validated dict to `request.validated` so
    the handler can pull from a single well-typed source.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from flask import request, jsonify, g


# Type coercion policy:
#   - bool is NOT accepted as int (the two are widely confused and
#     JSON `true`/`false` shouldn't silently count toward a spend_limit
#     or a TTL).
_ALLOWED_TYPES: dict[type, tuple[type, ...]] = {
    str:   (str,),
    int:   (int,),  # deliberately rejects bool
    float: (int, float),  # ints coerce to floats
    bool:  (bool,),
    list:  (list,),
    dict:  (dict,),
}


class _ValidationError(Exception):
    """Internal: short-circuit with a structured 400 reply."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"{field}: {reason}")


def _check_field(name: str, value: Any, spec: dict[str, Any]) -> Any:
    """Validate a single field against its spec, returning the (possibly
    coerced) value. Raises _ValidationError on any issue."""
    want_type = spec.get("type")
    if want_type is not None:
        allowed = _ALLOWED_TYPES.get(want_type, (want_type,))
        if type(value) in (bool,) and want_type in (int, float):
            raise _ValidationError(name, f"expected {want_type.__name__}, got bool")
        if not isinstance(value, allowed):
            raise _ValidationError(
                name, f"expected {want_type.__name__}, got {type(value).__name__}"
            )
        if want_type is float and isinstance(value, int):
            value = float(value)

    if "min" in spec and value < spec["min"]:
        raise _ValidationError(name, f"must be >= {spec['min']}")
    if "max" in spec and value > spec["max"]:
        raise _ValidationError(name, f"must be <= {spec['max']}")
    if "maxlen" in spec and hasattr(value, "__len__"):
        if len(value) > spec["maxlen"]:
            raise _ValidationError(name, f"length exceeds {spec['maxlen']}")
    if "choices" in spec and value not in spec["choices"]:
        raise _ValidationError(
            name, f"must be one of {sorted(spec['choices'])}"
        )
    return value


def validate_body(schema: dict[str, dict[str, Any]]) -> Callable[[Callable], Callable]:
    """Decorator that validates `request.json` against `schema`.

    Unknown fields are silently ignored (forward compatibility) — Haldir
    SDKs may send new fields that older server versions don't know about,
    and we'd rather accept-and-ignore than break the flow.
    """

    # Materialize iteration order once: preserves spec-declared order so
    # the first failure wins deterministically.
    items = list(schema.items())

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            raw = request.get_json(silent=True) or {}
            if not isinstance(raw, dict):
                return _fail("body", "request body must be a JSON object")

            validated: dict[str, Any] = {}
            for name, spec in items:
                if name in raw:
                    try:
                        validated[name] = _check_field(name, raw[name], spec)
                    except _ValidationError as e:
                        return _fail(e.field, e.reason)
                elif spec.get("required"):
                    return _fail(name, "field is required")
                elif "default" in spec:
                    validated[name] = spec["default"]
            # Expose to the handler.
            request.validated = validated  # type: ignore[attr-defined]
            return fn(*args, **kwargs)

        # Stash the schema on the wrapper so the OpenAPI generator (and
        # anyone else wanting to introspect the request contract) can
        # pull it back off the Flask view without re-parsing source.
        wrapper.__haldir_schema__ = schema  # type: ignore[attr-defined]
        return wrapper

    return decorator


def _fail(field: str, reason: str):  # type: ignore[no-untyped-def]
    payload = {
        "error": f"Invalid request body: {field} — {reason}",
        "code": "invalid_request",
        "field": field,
        "reason": reason,
        "request_id": getattr(g, "request_id", ""),
    }
    return jsonify(payload), 400
