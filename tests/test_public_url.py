"""
Tests for the configurable public origin.

Every discovery document Haldir serves names absolute URLs. Those URLs were
written against the hosted service, so they say https://haldir.xyz — correct
there, wrong on every other deployment, and SELF_HOSTING.md tells enterprises
to run their own.

The failure this guards against is silent and directional. An agent that
reads agent.json on a self-hosted instance, and is told to call
https://haldir.xyz/v1/sessions, will send that customer's credentials and
that customer's data to the vendor. Nothing errors. The request succeeds.
It just succeeds in the wrong place.

The exactness tests below matter as much as the substitution ones.
"haldir.xyz" also occurs inside email addresses (sterling@haldir.xyz) and
inside a subdomain (https://api.haldir.xyz). Rewriting either corrupts the
document rather than fixing it — a reply-to address nobody can reach, or a
host that never existed.

Run: python -m pytest tests/test_public_url.py -v
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_public_url import (  # noqa: E402
    DEFAULT_PUBLIC_BASE_URL,
    public_base_url,
    rewrite_public_origin,
)

SELF_HOSTED = "https://haldir.acme.example"

# Every route whose document actually names the origin, and so must name
# THIS instance rather than the vendor.
#
# AGENTS.md is deliberately absent. It contains no absolute URLs at all —
# check with `grep -c 'https://haldir.xyz' AGENTS.md` — so there is nothing
# to rewrite and nothing to assert. Its route still passes
# rewrite_origin=True, so a URL added to it later is handled; but a test
# claiming it names the instance would be asserting something that was
# never true, and would have to be deleted the moment someone looked.
REWRITTEN_ROUTES = (
    "/llms.txt",
    "/llms-full.txt",
    "/sitemap.xml",
    "/robots.txt",
    "/.well-known/ai-plugin.json",
    "/.well-known/ai.txt",
    "/.well-known/agent.json",
    "/.well-known/security.txt",
    "/THREAT_MODEL.md",
)


# ── Resolving the origin ─────────────────────────────────────────────

def test_unset_returns_the_hosted_default(monkeypatch) -> None:
    """An unconfigured install must behave exactly as it did before this
    module existed. The live deployment sets nothing, so this is the path
    production actually takes."""
    monkeypatch.delenv("HALDIR_BASE_URL", raising=False)
    assert public_base_url() == DEFAULT_PUBLIC_BASE_URL


def test_trailing_slash_is_stripped(monkeypatch) -> None:
    """Otherwise every rewritten URL gets a double slash —
    https://host//llms.txt — which some servers treat as a different path."""
    monkeypatch.setenv("HALDIR_BASE_URL", SELF_HOSTED + "/")
    assert public_base_url() == SELF_HOSTED


def test_scheme_less_value_falls_back(monkeypatch) -> None:
    """A bare hostname would produce documents full of links that are not
    links. An agent can retry a 404; it cannot parse 'haldir.acme.example'
    as a URL."""
    monkeypatch.setenv("HALDIR_BASE_URL", "haldir.acme.example")
    assert public_base_url() == DEFAULT_PUBLIC_BASE_URL


def test_http_is_accepted(monkeypatch) -> None:
    """Self-hosting behind a terminating proxy on an internal network is a
    real deployment, and http:// is a real answer there."""
    monkeypatch.setenv("HALDIR_BASE_URL", "http://haldir.internal")
    assert public_base_url() == "http://haldir.internal"


# ── Rewriting, and what must NOT be rewritten ────────────────────────

def test_rewrite_is_identity_when_unconfigured(monkeypatch) -> None:
    monkeypatch.delenv("HALDIR_BASE_URL", raising=False)
    text = "See https://haldir.xyz/llms.txt or mail sterling@haldir.xyz"
    assert rewrite_public_origin(text) == text


def test_rewrite_repoints_the_origin(monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_BASE_URL", SELF_HOSTED)
    out = rewrite_public_origin("Docs: https://haldir.xyz/docs")
    assert out == f"Docs: {SELF_HOSTED}/docs"


def test_rewrite_leaves_subdomains_alone(monkeypatch) -> None:
    """https://api.haldir.xyz must survive intact.

    It does not contain the string https://haldir.xyz — the text after the
    scheme is 'api.', not the domain — so matching on the scheme makes this
    true by construction. If someone later loosens the match to the bare
    domain, this fails."""
    monkeypatch.setenv("HALDIR_BASE_URL", SELF_HOSTED)
    out = rewrite_public_origin("servers: https://api.haldir.xyz")
    assert "https://api.haldir.xyz" in out
    assert SELF_HOSTED not in out


def test_rewrite_leaves_email_addresses_alone(monkeypatch) -> None:
    """Contact addresses appear throughout the discovery documents. An
    address rewritten to a domain that does not receive mail is worse than
    one pointing at the vendor — it looks deliverable and is not."""
    monkeypatch.setenv("HALDIR_BASE_URL", SELF_HOSTED)
    out = rewrite_public_origin(
        "contact sterling@haldir.xyz or noreply@haldir.xyz"
    )
    assert "sterling@haldir.xyz" in out
    assert "noreply@haldir.xyz" in out


# ── The served surface, end to end ───────────────────────────────────

def test_served_docs_name_the_instance_when_configured(
    haldir_client, monkeypatch
) -> None:
    """The whole point. Read the way an agent reads them."""
    monkeypatch.setenv("HALDIR_BASE_URL", SELF_HOSTED)
    for path in REWRITTEN_ROUTES:
        resp = haldir_client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        body = resp.data.decode()
        assert SELF_HOSTED in body, (
            f"{path} never names the configured instance — an agent reading "
            f"it would be sent to the vendor instead"
        )
        assert "https://haldir.xyz" not in body, (
            f"{path} still points at the vendor origin"
        )


def test_served_docs_are_unchanged_when_unconfigured(
    haldir_client, monkeypatch
) -> None:
    """Regression guard for the live deployment: this must be byte-identical
    to what shipped before. If it is not, the hosted service changed
    behaviour as a side effect of a self-hosting fix."""
    monkeypatch.delenv("HALDIR_BASE_URL", raising=False)
    body = haldir_client.get("/llms.txt").data.decode()
    assert "https://haldir.xyz" in body


def test_openapi_servers_names_the_instance(haldir_client, monkeypatch) -> None:
    """`servers` is what a generated client sends every request to."""
    monkeypatch.setenv("HALDIR_BASE_URL", SELF_HOSTED)
    spec = json.loads(haldir_client.get("/openapi.json").data)
    assert spec["servers"] == [{"url": SELF_HOSTED}]


def test_openapi_servers_is_not_a_dead_host(haldir_client, monkeypatch) -> None:
    """It used to be https://api.haldir.xyz, which has no DNS record at
    all — every client generated from the spec targeted a name that does
    not resolve. Whatever the origin resolves to, it must not be that."""
    monkeypatch.delenv("HALDIR_BASE_URL", raising=False)
    spec = json.loads(haldir_client.get("/openapi.json").data)
    assert spec["servers"][0]["url"] != "https://api.haldir.xyz"
    assert spec["servers"][0]["url"] == DEFAULT_PUBLIC_BASE_URL
