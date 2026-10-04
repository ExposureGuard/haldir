"""
Tests for haldir_openapi — the spec generator that walks the Flask
route table and emits OpenAPI 3.1.

Run: python -m pytest tests/test_openapi.py -v
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
from haldir_openapi import (  # noqa: E402
    generate_openapi,
    _request_body_from_schema,
    _extract_path_params,
    _schema_for_field,
)


# ── Field-level schema translation ──────────────────────────────────────

def test_str_field_with_maxlen() -> None:
    out = _schema_for_field({"type": str, "maxlen": 128})
    assert out == {"type": "string", "maxLength": 128}


def test_int_field_with_range() -> None:
    out = _schema_for_field({"type": int, "min": 0, "max": 100})
    assert out == {"type": "integer", "minimum": 0, "maximum": 100}


def test_float_field_default_included() -> None:
    out = _schema_for_field({"type": float, "default": 1.5, "min": 0.0})
    assert out["type"] == "number"
    assert out["default"] == 1.5
    assert out["minimum"] == 0.0


def test_none_default_excluded() -> None:
    """default=None means `absent` — shouldn't leak into the OpenAPI
    schema as a default value."""
    out = _schema_for_field({"type": float, "default": None})
    assert "default" not in out


def test_choices_becomes_enum() -> None:
    out = _schema_for_field({"type": str, "choices": ["a", "b", "c"]})
    assert out["enum"] == ["a", "b", "c"]


# ── requestBody assembly ───────────────────────────────────────────────

def test_request_body_required_fields_surface() -> None:
    schema = {
        "agent_id": {"type": str, "required": True, "maxlen": 128},
        "ttl":      {"type": int, "default": 3600, "min": 0},
    }
    rb = _request_body_from_schema(schema)
    assert rb["required"] is True
    body = rb["content"]["application/json"]["schema"]
    assert body["required"] == ["agent_id"]
    assert "agent_id" in body["properties"]
    assert body["properties"]["ttl"]["default"] == 3600
    assert body["additionalProperties"] is False


# ── Path parameter extraction ──────────────────────────────────────────

def test_simple_path_param() -> None:
    path, params = _extract_path_params("/v1/sessions/<session_id>")
    assert path == "/v1/sessions/{session_id}"
    assert params == [
        {"name": "session_id", "in": "path", "required": True,
         "schema": {"type": "string"}},
    ]


def test_int_converter() -> None:
    _, params = _extract_path_params("/users/<int:user_id>")
    assert params[0]["schema"]["type"] == "integer"


def test_multiple_path_params() -> None:
    path, params = _extract_path_params("/v1/foo/<a>/bar/<int:b>")
    assert path == "/v1/foo/{a}/bar/{b}"
    assert [p["name"] for p in params] == ["a", "b"]


# ── Spec-wide shape ─────────────────────────────────────────────────────

def test_spec_is_openapi_3_1() -> None:
    spec = generate_openapi(api.app)
    assert spec["openapi"].startswith("3.1")
    assert spec["info"]["title"] == "Haldir"


def test_spec_has_paths() -> None:
    spec = generate_openapi(api.app)
    assert len(spec["paths"]) > 10
    # Key endpoints all show up.
    assert "/v1/sessions" in spec["paths"]
    assert "/v1/payments/authorize" in spec["paths"]
    assert "/v1/audit" in spec["paths"]
    assert "/healthz" in spec["paths"]


def test_spec_components_include_error_envelope_and_security() -> None:
    spec = generate_openapi(api.app)
    comps = spec["components"]
    assert "ErrorEnvelope" in comps["schemas"]
    assert "ApiKeyBearer" in comps["securitySchemes"]
    assert "IdempotencyKey" in comps["securitySchemes"]
    # Shared error responses referenced by every operation.
    assert "RateLimited" in comps["responses"]
    assert "PayloadTooLarge" in comps["responses"]


def test_spec_includes_validated_schemas() -> None:
    """/v1/sessions has @validate_body — its POST must carry a
    requestBody with the declared properties."""
    spec = generate_openapi(api.app)
    post = spec["paths"]["/v1/sessions"]["post"]
    body = post["requestBody"]["content"]["application/json"]["schema"]
    assert "agent_id" in body["properties"]
    assert body["required"] == ["agent_id"]


def test_spec_marks_idempotency_key_on_mutating_post() -> None:
    """Every validate-body-decorated POST should list the
    Idempotency-Key header parameter so the Swagger try-it-out UI
    exposes it."""
    spec = generate_openapi(api.app)
    post = spec["paths"]["/v1/sessions"]["post"]
    header_refs = [
        p for p in post["parameters"]
        if isinstance(p, dict) and "$ref" in p and "IdempotencyKey" in p["$ref"]
    ]
    assert header_refs


def test_tags_group_routes() -> None:
    spec = generate_openapi(api.app)
    tag_names = {t["name"] for t in spec["tags"]}
    assert {"gate", "vault", "watch", "proxy", "billing", "platform"} <= tag_names


# ── End-to-end via /openapi.json + /swagger ────────────────────────────

def test_openapi_json_endpoint_serves_spec(haldir_client) -> None:
    r = haldir_client.get("/openapi.json")
    assert r.status_code == 200
    spec = r.get_json()
    assert spec["openapi"].startswith("3.1")
    assert "/v1/sessions" in spec["paths"]


def test_swagger_ui_endpoint_renders_html(haldir_client) -> None:
    r = haldir_client.get("/swagger")
    assert r.status_code == 200
    assert "text/html" in r.content_type
    body = r.data.decode()
    assert "swagger-ui" in body.lower()
    assert "/openapi.json" in body


def test_committed_spec_matches_the_generated_one() -> None:
    """The openapi.json in the repo is a published artifact, not a by-product.

    The served spec is generated from `app.url_map` on every request, so it
    is always right. The committed file is not: nobody regenerates it, and it
    had been five months stale — documenting 24 of the 80 live paths, with
    the whole `.well-known/` discovery surface and `/cloud` missing.

    That matters because the file is what a reader gets who fetches the
    repository rather than the URL: agent registries, submission tooling, and
    anyone browsing. They would be working from an API description that is
    quietly wrong, which is worse than one that is obviously missing.

    Regenerate after adding or removing a route:

        python - <<'EOF'
        import json, api, haldir_openapi
        json.dump(haldir_openapi.generate_openapi(api.app),
                  open("openapi.json", "w"), indent=2)
        EOF
    """
    import json
    from pathlib import Path

    committed = json.loads((Path(__file__).resolve().parent.parent / "openapi.json").read_text())
    generated = generate_openapi(api.app)

    assert set(committed["paths"]) == set(generated["paths"]), (
        "openapi.json has drifted from the live routes — regenerate it "
        "(added: %s, removed: %s)" % (
            sorted(set(generated["paths"]) - set(committed["paths"]))[:8],
            sorted(set(committed["paths"]) - set(generated["paths"]))[:8],
        )
    )
    assert committed == generated, "openapi.json differs beyond its path list"


# ── Security is declared per operation, not blanket ─────────────────────

def test_public_operations_declare_themselves_public() -> None:
    """The document's top-level `security` applies bearer auth to every
    operation that does not override it. That described /healthz, the
    discovery documents and the demo-key mint as requiring a key — none of
    which take one. Public operations now say `security: []` explicitly,
    which is what the field exists for."""
    spec = generate_openapi(api.app)
    for path in ("/healthz", "/.well-known/agent.json", "/v1/demo/key"):
        for method, op in spec["paths"][path].items():
            assert op.get("security") == [], (
                f"{method.upper()} {path} is public but the spec applies the "
                f"document-wide bearer requirement to it"
            )


def test_key_gated_operations_keep_the_bearer_requirement() -> None:
    """The other half of the pair: a route marked by `require_api_key` must
    NOT be declared public. Both examples stack decorators on top of it
    (@validate_body, @require_scope), which is the case `@wraps` has to carry
    the marker through."""
    spec = generate_openapi(api.app)
    assert "security" not in spec["paths"]["/v1/sessions"]["post"]
    assert "security" not in spec["paths"]["/v1/keys"]["get"]


def test_the_first_key_mint_is_not_declared_as_key_gated() -> None:
    """POST /v1/keys bootstraps the first key from HALDIR_BOOTSTRAP_TOKEN and
    takes no API key; it must not inherit the bearer requirement."""
    spec = generate_openapi(api.app)
    assert spec["paths"]["/v1/keys"]["post"]["security"] == []


def test_plain_text_discovery_documents_are_not_described_as_json() -> None:
    """`.well-known/ai.txt` and `security.txt` are plain text; with the
    blanket response set they were documented as returning 201 Created and
    401 Unauthorized. The generator's stated rule is "the JSON surface", so
    they are skipped. `/ai.txt` — which no route has served for three
    releases — was the entry meant to do this."""
    spec = generate_openapi(api.app)
    assert "/.well-known/ai.txt" not in spec["paths"]
    assert "/.well-known/security.txt" not in spec["paths"]
    # The JSON documents under the same prefix are still described.
    assert "/.well-known/agent.json" in spec["paths"]
