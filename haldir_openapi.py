"""
Haldir OpenAPI 3.1 spec generator.

Walks a Flask app's URL map and emits a machine-readable OpenAPI 3.1
document describing every route. Pulls request-body schemas off any
handler decorated with `@validate_body` (the schema is stashed on the
wrapper at decoration time).

Design goals:

  - Zero extra dependencies. The spec is just a dict, rendered through
    Flask's built-in `jsonify`. No apispec / marshmallow / pydantic.

  - No hand-maintained schema file. The OpenAPI doc is always the exact
    shape of the live API; diverging is structurally impossible.

  - Gracefully incomplete. Routes without a validate_body decorator are
    still listed but carry no requestBody schema — the doc degrades to
    "here's the path and method" rather than breaking.

Currently covers: paths, methods, path parameters (inferred from
Flask converters like `<int:id>` / `<session_id>`), request-body
JSON schemas (from @validate_body), API-key security scheme, standard
error envelopes. Response schemas are not yet modeled — follow-up.
"""

from __future__ import annotations

from typing import Any

# Mapping from validate_body Python types → OpenAPI primitive types.
_TYPE_MAP: dict[type, dict[str, Any]] = {
    str:   {"type": "string"},
    int:   {"type": "integer"},
    float: {"type": "number"},
    bool:  {"type": "boolean"},
    list:  {"type": "array", "items": {}},
    dict:  {"type": "object"},
}


def _schema_for_field(spec: dict[str, Any]) -> dict[str, Any]:
    """Render a single validate_body field spec as an OpenAPI schema."""
    py_type = spec.get("type")
    out: dict[str, Any] = {}
    if py_type is not None and py_type in _TYPE_MAP:
        out.update(_TYPE_MAP[py_type])
    if "min" in spec:
        out["minimum"] = spec["min"]
    if "max" in spec:
        out["maximum"] = spec["max"]
    if "maxlen" in spec:
        if out.get("type") == "string":
            out["maxLength"] = spec["maxlen"]
        elif out.get("type") == "array":
            out["maxItems"] = spec["maxlen"]
    if "choices" in spec:
        out["enum"] = list(spec["choices"])
    if "default" in spec and spec["default"] is not None:
        out["default"] = spec["default"]
    return out


def _request_body_from_schema(schema: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Convert a @validate_body schema to an OpenAPI requestBody."""
    properties: dict[str, Any] = {}
    required: list[str] = []
    for name, spec in schema.items():
        properties[name] = _schema_for_field(spec)
        if spec.get("required"):
            required.append(name)
    body_schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        body_schema["required"] = required
    return {
        "required": True,
        "content": {"application/json": {"schema": body_schema}},
    }


def _extract_path_params(rule: str) -> tuple[str, list[dict[str, Any]]]:
    """Turn Flask's `/foo/<int:id>/bar/<name>` into OpenAPI's
    `/foo/{id}/bar/{name}` plus the parameter list."""
    import re
    params: list[dict[str, Any]] = []
    # Flask converters: <converter:name> or <name> (defaults to string).
    pattern = re.compile(r"<(?:(?P<conv>[a-z]+):)?(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)>")

    def replace(m: re.Match[str]) -> str:
        conv = m.group("conv") or "string"
        name = m.group("name")
        oapi_type = {
            "int": "integer", "float": "number",
            "path": "string", "uuid": "string", "string": "string",
        }.get(conv, "string")
        params.append({
            "name": name,
            "in": "path",
            "required": True,
            "schema": {"type": oapi_type},
        })
        return "{" + name + "}"

    oapi_path = pattern.sub(replace, rule)
    return oapi_path, params


def _default_responses() -> dict[str, Any]:
    """Every endpoint shares the same error-envelope contract, so point
    each response at the reusable component rather than restating it."""
    return {
        "400": {"$ref": "#/components/responses/ValidationError"},
        "401": {"$ref": "#/components/responses/Unauthorized"},
        "403": {"$ref": "#/components/responses/Forbidden"},
        "404": {"$ref": "#/components/responses/NotFound"},
        "413": {"$ref": "#/components/responses/PayloadTooLarge"},
        "422": {"$ref": "#/components/responses/IdempotencyMismatch"},
        "429": {"$ref": "#/components/responses/RateLimited"},
        "500": {"$ref": "#/components/responses/InternalError"},
    }


def _error_envelope_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["error", "code", "request_id"],
        "properties": {
            "error":      {"type": "string", "description": "Human-readable message"},
            "code":       {"type": "string", "description": "Machine-readable error code"},
            "request_id": {"type": "string", "description": "Correlate with server logs"},
        },
        "additionalProperties": True,
    }


def _components() -> dict[str, Any]:
    """Reusable components: security schemes + shared error responses."""
    ref_to_envelope = {
        "description": "",
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/ErrorEnvelope"},
            },
        },
    }

    def make(desc: str) -> dict[str, Any]:
        r = {
            "description": desc,
            "content": ref_to_envelope["content"],
        }
        return r

    return {
        "schemas": {
            "ErrorEnvelope": _error_envelope_schema(),
        },
        "securitySchemes": {
            "ApiKeyBearer": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "hld_...",
                "description": (
                    "Haldir API key. Obtain via POST /v1/keys "
                    "(bootstrap) or your tenant admin."
                ),
            },
            "IdempotencyKey": {
                "type": "apiKey",
                "in": "header",
                "name": "Idempotency-Key",
                "description": (
                    "Optional UUID; safe retries on every mutating POST."
                ),
            },
        },
        "responses": {
            "ValidationError":      make("Request body failed schema validation"),
            "Unauthorized":         make("Missing or invalid API key"),
            "Forbidden":            make("Valid caller, denied action"),
            "NotFound":             make("Endpoint or resource not found"),
            "PayloadTooLarge":      make("Request body exceeded 1 MiB limit"),
            "IdempotencyMismatch":  make("Idempotency-Key reused with a different body"),
            "RateLimited":          make("Rate-limit exceeded (tier-dependent)"),
            "InternalError":        make("Unhandled server error"),
        },
    }


def generate_openapi(app: Any, version: str = "0.2.3") -> dict[str, Any]:
    """Build the OpenAPI 3.1 document for a Flask app."""
    spec: dict[str, Any] = {
        "openapi": "3.1.0",
        "info": {
            "title": "Haldir",
            "version": version,
            "description": (
                "Identity, secrets, spend, and audit for AI agents. "
                "Every mutating POST accepts an optional Idempotency-Key "
                "header for safe retries."
            ),
            "contact": {
                "name": "Haldir",
                "url": "https://haldir.xyz",
                "email": "sterling@haldir.xyz",
            },
            "license": {"name": "MIT"},
        },
        "servers": [{"url": "https://api.haldir.xyz"}],
        "components": _components(),
        "security": [{"ApiKeyBearer": []}],
        "paths": {},
        "tags": [
            {"name": "gate", "description": "Sessions, scopes, identity"},
            {"name": "vault", "description": "Encrypted secrets + payments"},
            {"name": "watch", "description": "Audit trail, spend, webhooks"},
            {"name": "proxy", "description": "Policy-gated MCP tool calls"},
            {"name": "billing", "description": "Stripe checkout + webhooks"},
            {"name": "platform", "description": "Health, metrics, docs"},
        ],
    }

    # Walk every Flask rule; skip the HTML pages, assets, and internal
    # routes — an OpenAPI doc should only describe the JSON surface.
    _SKIP_PREFIXES = ("/static", "/_debug")
    _SKIP_EXACT = {"/", "/docs", "/pricing", "/quickstart", "/sitemap.xml",
                   "/robots.txt", "/ai.txt", "/llms.txt", "/llms-full.txt",
                   "/status", "/demo"}

    paths: dict[str, dict[str, Any]] = spec["paths"]

    for rule in app.url_map.iter_rules():
        raw_path = rule.rule
        if raw_path in _SKIP_EXACT:
            continue
        if any(raw_path.startswith(p) for p in _SKIP_PREFIXES):
            continue
        # Skip the static demo-asset route (the SVG, etc.) — not part
        # of the JSON API surface.
        if raw_path.startswith("/demo/"):
            continue
        # Skip anything that renders HTML (heuristic: no JSON under /).
        if rule.endpoint == "static":
            continue

        oapi_path, path_params = _extract_path_params(raw_path)
        view_fn = app.view_functions.get(rule.endpoint)
        schema = getattr(view_fn, "__haldir_schema__", None)

        # Determine tag from path prefix for clean grouping in Swagger UI.
        tag = _tag_for(raw_path)

        for method in sorted(rule.methods or ()):
            if method in ("HEAD", "OPTIONS"):
                continue

            op: dict[str, Any] = {
                "operationId": f"{method.lower()}_{rule.endpoint}",
                "summary": _clean_docstring(view_fn),
                "tags": [tag],
                "parameters": list(path_params),
                "responses": {
                    "200": {"description": "Success"},
                    "201": {"description": "Created"},
                    **_default_responses(),
                },
            }

            if method == "POST" and schema:
                op["requestBody"] = _request_body_from_schema(schema)
                # Mutating POSTs accept Idempotency-Key.
                op["parameters"] = op["parameters"] + [
                    {"$ref": "#/components/parameters/IdempotencyKeyHeader"}
                ]

            paths.setdefault(oapi_path, {})[method.lower()] = op

    # Declare the reusable Idempotency-Key header parameter referenced
    # by every mutating POST operation above.
    spec["components"].setdefault("parameters", {})
    spec["components"]["parameters"]["IdempotencyKeyHeader"] = {
        "name": "Idempotency-Key",
        "in": "header",
        "required": False,
        "description": (
            "Client-generated UUID to make this POST safe to retry. "
            "Replays with the same key and body return the cached response; "
            "replays with the same key but a different body return 422."
        ),
        "schema": {"type": "string", "maxLength": 128},
    }

    return spec


def _clean_docstring(fn: Any) -> str:
    """First line of a view function's docstring, or a sensible fallback."""
    doc = (getattr(fn, "__doc__", None) or "").strip()
    if not doc:
        return ""
    return doc.split("\n", 1)[0].strip()


def _tag_for(path: str) -> str:
    """Coarse tag from the URL prefix — keeps Swagger UI grouped nicely."""
    if path.startswith("/v1/sessions") or path.startswith("/v1/keys"):
        return "gate"
    if path.startswith("/v1/secrets") or path.startswith("/v1/payments"):
        return "vault"
    if path.startswith("/v1/audit") or path.startswith("/v1/webhooks") or path.startswith("/v1/approvals"):
        return "watch"
    if path.startswith("/v1/proxy"):
        return "proxy"
    if path.startswith("/v1/billing"):
        return "billing"
    return "platform"
