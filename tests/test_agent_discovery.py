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


def test_ai_plugin_advertises_integration_packages(haldir_client) -> None:
    """Agents doing tool-discovery via ai-plugin.json should learn
    about the 2-line adoption path without scraping the README."""
    r = haldir_client.get("/.well-known/ai-plugin.json")
    desc = json.loads(r.data)["description_for_model"]
    for pkg in ("langchain-haldir", "crewai-haldir", "llamaindex-haldir"):
        assert pkg in desc, f"ai-plugin.json doesn't advertise {pkg!r}"


def test_ai_plugin_advertises_rekor_verifier(haldir_client) -> None:
    """The §10.3b closer must be visible to agents picking Haldir
    from a tool list — it's the differentiating trust claim."""
    r = haldir_client.get("/.well-known/ai-plugin.json")
    desc = json.loads(r.data)["description_for_model"]
    assert "Rekor" in desc or "mirror" in desc.lower()


# ── agent.json — single-entry-point manifest ────────────────────────

def test_agent_json_served(haldir_client) -> None:
    """The /.well-known/agent.json manifest is the canonical single-
    fetch entry point for agents doing capability discovery. It
    describes every transport (REST, MCP stdio, MCP HTTP, x402),
    every integration package, every trust signal, and where
    Haldir's already listed in the ecosystem."""
    r = haldir_client.get("/.well-known/agent.json")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/json")
    body = json.loads(r.data)
    # Structural contract — these keys are what agent frameworks
    # key off of when parsing the manifest.
    for key in ("name", "display_name", "description", "entry_points",
                 "capabilities", "integrations", "trust_signals"):
        assert key in body, f"agent.json missing required top-level key: {key!r}"
    # Entry points must cover the four transports.
    entry_points = body["entry_points"]
    for transport in ("rest_api", "mcp_stdio", "mcp_http", "x402"):
        assert transport in entry_points, (
            f"agent.json missing entry_points.{transport}"
        )
    # MCP stdio entry must carry the full Claude-Desktop-style config
    # block so a user can copy-paste it into their client config.
    stdio = entry_points["mcp_stdio"]
    assert "claude_desktop_config" in stdio
    assert stdio["claude_desktop_config"]["mcpServers"]["haldir"]["command"] == "haldir"


def test_agent_json_lists_integration_packages(haldir_client) -> None:
    body = json.loads(
        haldir_client.get("/.well-known/agent.json").data,
    )
    for fw in ("langchain", "crewai", "llamaindex"):
        assert fw in body["integrations"], (
            f"agent.json integrations missing {fw!r}"
        )
        entry = body["integrations"][fw]
        assert entry["package"].endswith("-haldir")
        assert entry["version"].startswith("0.2")


def test_agent_json_covers_rekor_verifier(haldir_client) -> None:
    body = json.loads(
        haldir_client.get("/.well-known/agent.json").data,
    )
    signals = body["trust_signals"]
    assert "rekor_receipt_verifier" in signals
    assert "ed25519_sth" in signals
    assert "external_mirror" in signals


# ── FAQPage JSON-LD on landing ──────────────────────────────────────

def test_landing_has_faq_jsonld(haldir_client) -> None:
    """Structured Q&A makes Haldir answerable by LLM-powered search
    (Perplexity, Phind, Claude web search) without them having to
    parse the landing page's free-form prose."""
    body = haldir_client.get("/").data.decode()
    assert '"@type": "FAQPage"' in body
    # At minimum, these topics must be in the FAQ so agents see them:
    for must_mention in ("LangChain", "MCP", "Rekor", "tamper", "x402"):
        assert must_mention in body, (
            f"FAQPage JSON-LD missing mention of {must_mention!r}"
        )


# ── Sitemap ─────────────────────────────────────────────────────────

def test_sitemap_includes_todays_routes(haldir_client) -> None:
    """Every route we shipped this week must be in the sitemap so
    crawlers find it on the next pass. Rot check: if someone adds a
    new endpoint and forgets to update the sitemap, this test
    surfaces it."""
    body = haldir_client.get("/sitemap.xml").data.decode()
    for route in (
        "/demo/tamper",
        "/AGENTS.md",
        "/THREAT_MODEL.md",
        "/.well-known/jwks.json",
        "/.well-known/x402.json",
        "/.well-known/agent.json",
        "/v1/x402/manifest",
    ):
        assert route in body, f"sitemap.xml missing {route!r}"


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


def test_threat_model_served(haldir_client) -> None:
    """THREAT_MODEL.md is what enterprise security buyers + technical
    investors read first. Has to be at /THREAT_MODEL.md AND has to
    actually carry STRIDE coverage + named adversaries + residual-
    risk declarations — not marketing copy."""
    r = haldir_client.get("/THREAT_MODEL.md")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/markdown")
    body = r.data.decode()
    # Required structural pieces. If any of these go missing the doc
    # has been gutted into marketing.
    for marker in (
        "STRIDE",
        "Adversaries",
        "Residual",
        "Out of scope",
        "disclosure",
        "Cryptographic primitives",
        "AES-256-GCM",
        "RFC 6962",
        "Ed25519",
        "anti-equivocation",
    ):
        assert marker.lower() in body.lower(), (
            f"THREAT_MODEL.md missing required marker: {marker!r}"
        )
    # Disclosure contact must be present.
    assert "sterling@" in body or "security.txt" in body


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
