"""
Tests for the agent-discovery surface.

An AI agent or crawler doing tool discovery against Haldir walks a
fixed set of canonical URLs. Every one of them needs to:

  1. Return 200 (not 404, not 500).
  2. Return the right Content-Type so downstream parsers don't fail.
  3. Carry content that actually advertises Haldir's capabilities —
     no stale or broken-reference documents.

If any of these break, Haldir falls out of tool registries silently
(no error, just not-listed), which is exactly the failure mode that's
hardest to notice in prod. These tests pin the contract.

Run: python -m pytest tests/test_agent_discovery.py -v
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Core discovery URLs ──────────────────────────────────────────────

def test_llms_txt_served(haldir_client) -> None:
    r = haldir_client.get("/llms.txt")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/plain")
    body = r.data.decode()
    # Must advertise Haldir and the Merkle/tamper-evidence story.
    assert "Haldir" in body
    assert "RFC 6962" in body
    assert "/v1/audit/tree-head" in body
    assert "/demo/tamper" in body


def test_llms_full_txt_served(haldir_client) -> None:
    r = haldir_client.get("/llms-full.txt")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/plain")
    assert b"Haldir" in r.data


def test_robots_txt_welcomes_llm_crawlers(haldir_client) -> None:
    r = haldir_client.get("/robots.txt")
    assert r.status_code == 200
    body = r.data.decode()
    # Haldir explicitly allows known LLM crawlers — critical for agent
    # discovery through search + tool-registry indexes.
    for ua in ("GPTBot", "ClaudeBot", "ChatGPT-User", "anthropic-ai"):
        assert ua in body, f"robots.txt missing user-agent {ua!r}"


def test_ai_plugin_json_served(haldir_client) -> None:
    r = haldir_client.get("/.well-known/ai-plugin.json")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/json")
    spec = json.loads(r.data)
    assert spec["schema_version"]
    assert spec["name_for_model"] == "haldir"
    # The model-facing description must mention the governance primitives
    # so an LLM tool-router knows WHEN to pick Haldir.
    desc = spec["description_for_model"]
    assert "session" in desc.lower()
    assert "audit" in desc.lower()
    assert "scope" in desc.lower() or "scoped" in desc.lower()
    # And points at the OpenAPI so clients can codegen against it.
    assert spec["api"]["url"].endswith("/openapi.json")


def test_ai_plugin_mentions_tamper_evidence(haldir_client) -> None:
    """A technical investor / buyer scanning the model-description
    should see the differentiating capability — not just CRUD verbs."""
    r = haldir_client.get("/.well-known/ai-plugin.json")
    desc = json.loads(r.data)["description_for_model"]
    assert "RFC 6962" in desc or "Merkle" in desc or "tree-head" in desc.lower()


def test_ai_txt_served(haldir_client) -> None:
    r = haldir_client.get("/.well-known/ai.txt")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/plain")


def test_security_txt_served(haldir_client) -> None:
    r = haldir_client.get("/.well-known/security.txt")
    assert r.status_code == 200


def test_agents_md_served(haldir_client) -> None:
    """AGENTS.md is the emerging convention for AI coding agents
    (Cursor, Codex, Aider, Claude Code, Windsurf) to pick up project
    conventions. Mirror the on-disk file at the live site root."""
    r = haldir_client.get("/AGENTS.md")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/markdown")
    body = r.data.decode()
    # Key sections that tell an agent how to work this repo.
    for heading in ("Run + build commands", "Conventions",
                    "Public API contract"):
        assert heading in body, f"AGENTS.md missing section: {heading!r}"


# ── MCP discovery surface ────────────────────────────────────────────

def test_mcp_manifest_served(haldir_client) -> None:
    r = haldir_client.get("/.well-known/mcp/mcp.json")
    assert r.status_code == 200
    spec = json.loads(r.data)
    assert spec["name"] == "haldir"
    # An MCP client needs these to connect.
    assert spec["mcpEndpoint"]
    assert spec["authentication"]["type"] == "bearer"


def test_mcp_server_card_served(haldir_client) -> None:
    """The server-card merges on-disk richness with live tool state —
    gets 500 if the file is missing and MCP_TOOLS isn't importable."""
    r = haldir_client.get("/.well-known/mcp/server-card.json")
    assert r.status_code == 200
    card = json.loads(r.data)
    assert card["name"] == "haldir"
    # Live state layered in.
    assert "capabilities" in card
    assert "tools" in card and isinstance(card["tools"], list)
    # On-disk richness preserved.
    assert "use_cases" in card
    assert "trust_signals" in card
    assert card["trust_signals"]["rfc_6962_merkle"] is True


def test_server_card_has_tamper_demo_link(haldir_client) -> None:
    r = haldir_client.get("/.well-known/mcp/server-card.json")
    card = json.loads(r.data)
    assert card["links"]["tamper_demo"].endswith("/demo/tamper")


# ── OpenAPI spec ─────────────────────────────────────────────────────

def test_openapi_json_served(haldir_client) -> None:
    r = haldir_client.get("/openapi.json")
    assert r.status_code == 200
    spec = json.loads(r.data)
    assert spec["openapi"].startswith("3.")
    # The new tamper-evidence endpoints must be in the spec — agents
    # generating SDKs from OpenAPI need them.
    paths = spec["paths"]
    assert "/v1/audit/tree-head" in paths
    assert "/v1/audit/consistency-proof" in paths
    # The inclusion-proof endpoint has a path parameter.
    assert any("inclusion-proof" in p for p in paths)


# ── Cross-link integrity ─────────────────────────────────────────────

def test_llms_txt_links_resolve_locally(haldir_client) -> None:
    """Every https://haldir.xyz/... link in llms.txt that points at
    THIS service must actually return 200 here. Catches drift between
    the discovery doc and the live routes."""
    r = haldir_client.get("/llms.txt")
    body = r.data.decode()
    local_paths: set[str] = set()
    for line in body.splitlines():
        # Extract "https://haldir.xyz/..." and convert to a local path.
        idx = line.find("https://haldir.xyz/")
        if idx == -1:
            continue
        url = line[idx:].split()[0].rstrip(".,)")
        path = url.replace("https://haldir.xyz", "", 1)
        # Ignore the bare domain and query-string-heavy URLs — they hit
        # routes with their own auth flow that isn't in scope here.
        if not path or "?" in path:
            continue
        # Paths under /v1/ need auth; skip those for this probe.
        if path.startswith("/v1/"):
            continue
        local_paths.add(path)

    assert local_paths, "no local paths extracted from llms.txt"
    for path in sorted(local_paths):
        resp = haldir_client.get(path)
        # 200 or 302 (redirect to a landing) are both fine; anything
        # else means a broken discovery link.
        assert resp.status_code in (200, 302), (
            f"broken link in llms.txt: {path} → {resp.status_code}"
        )


def test_landing_page_has_jsonld_with_tamper_evidence(haldir_client) -> None:
    """The SoftwareApplication JSON-LD block on the landing page must
    include the Merkle / tamper-evidence featureList so Google and
    agent crawlers get structured signal about the differentiator."""
    r = haldir_client.get("/")
    body = r.data.decode()
    assert 'application/ld+json' in body
    assert "RFC 6962" in body or "Merkle" in body
