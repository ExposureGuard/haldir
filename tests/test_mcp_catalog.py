"""
Catalog invariants for Haldir's MCP tools.

`haldir_mcp_server.TOOLS` is the single source of truth for what Haldir
exposes over MCP. The hosted endpoint is checked against it in
test_mcp_http.py; this file checks the catalog itself, and checks that the
documents which advertise it still tell the truth.

Run: python -m pytest tests/test_mcp_catalog.py -v
"""

from __future__ import annotations

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import haldir_mcp_server  # noqa: E402

TOOLS = haldir_mcp_server.TOOLS
NAMES = [t["name"] for t in TOOLS]


# ── Catalog shape ────────────────────────────────────────────────────

def test_no_duplicate_tool_names() -> None:
    """Two tools with one name means one of them is unreachable — the
    dispatcher builds a dict keyed by name and the later entry wins."""
    dupes = {n for n in NAMES if NAMES.count(n) > 1}
    assert not dupes, f"duplicate tool names: {sorted(dupes)}"


def test_names_are_prefixed_and_snake_case() -> None:
    bad = [n for n in NAMES if not re.fullmatch(r"haldir_[a-z0-9_]+", n)]
    assert not bad, f"tool names must be haldir_snake_case: {bad}"


@pytest.mark.parametrize("tool", TOOLS, ids=NAMES)
def test_schema_is_well_formed(tool: dict) -> None:
    """A schema that requires a property it never declares is rejected by
    strict clients, and silently ignored by lenient ones — either way the
    caller gets a confusing failure instead of a validation message."""
    schema = tool["inputSchema"]
    assert schema["type"] == "object", f"{tool['name']}: inputSchema must be an object"

    props = set(schema.get("properties", {}))
    required = set(schema.get("required", []))
    undeclared = required - props
    assert not undeclared, (
        f"{tool['name']} requires {sorted(undeclared)} but does not declare "
        f"them in properties"
    )


@pytest.mark.parametrize("tool", TOOLS, ids=NAMES)
def test_every_tool_has_a_description_and_handler(tool: dict) -> None:
    assert tool.get("description", "").strip(), f"{tool['name']} has no description"
    assert callable(tool.get("handler")), f"{tool['name']} has no callable handler"


# ── Docs agree with the catalog ──────────────────────────────────────

def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.parametrize("doc", ["README.md", "llms.txt", "CONTRIBUTING.md"])
def test_doc_states_the_current_tool_count(doc: str) -> None:
    """The count is the claim that rots first — it read '10 tools' on three
    documents while the catalog held 19. Anchored on the word 'tools' so
    unrelated numbers elsewhere in the file are ignored."""
    text = _read(doc)
    claims = {int(m) for m in re.findall(r"\b(\d+)\s+tools\b", text)}
    if not claims:
        pytest.skip(f"{doc} makes no tool-count claim")
    assert claims == {len(TOOLS)}, (
        f"{doc} claims {sorted(claims)} tools; the catalog has {len(TOOLS)}"
    )


@pytest.mark.parametrize("doc", ["README.md", "llms.txt", "llms-full.txt", "CONTRIBUTING.md"])
def test_docs_do_not_advertise_retired_camel_case_names(doc: str) -> None:
    """The retired names — createSession, getAuditTrail and friends — sent
    callers to a tool that did not exist. They must not creep back into the
    documents, which is where a user copies names from.

    Only backticked and bare identifiers are considered, so the JavaScript
    SDK's own camelCase methods (which are a different, legitimate API)
    are not flagged — they appear in fenced ```js blocks, which are
    stripped before the search.
    """
    text = re.sub(r"```.*?```", "", _read(doc), flags=re.S)  # drop code fences
    retired = {n for n in ("createSession", "getSession", "revokeSession",
                           "checkPermission", "storeSecret", "getSecret",
                           "authorizePayment", "logAction", "getAuditTrail",
                           "getSpend")
               if re.search(rf"\b{re.escape(n)}\b", text)}
    assert not retired, f"{doc} still advertises retired tool names: {sorted(retired)}"


# ── A tool's arguments must name what the route reads ────────────────

def _body_keys_the_route_reads(handler: str) -> set[str]:
    """The JSON body keys the named handler in api.py actually reads.

    Read from the source rather than restated here. An earlier version of the
    test below hardcoded the names, which meant it would have stayed green
    while the route side moved on — the exact failure it exists to catch.
    """
    src = _read("api.py")
    start = src.find(f"def {handler}(")
    assert start >= 0, f"api.py has no handler named {handler!r}"
    tail = src[start:]
    nxt = re.search(r"\n(?=@app\.route|def |class )", tail[10:])
    body = tail[: nxt.start() + 10] if nxt else tail[:3000]
    return set(re.findall(r'data\.get\(\s*"([^"]+)"', body))


def test_the_approval_tools_name_what_the_route_reads() -> None:
    """A tool's arguments are sent verbatim as the request body, so a name the
    route does not read is an argument that silently does nothing.

    `haldir_request_approval` advertised `expires_in_s` while POST
    /v1/approvals/request reads `ttl`. The argument appeared in the schema,
    validated, and was then discarded — every approval got the 3600s default
    whatever the caller asked for, and nothing reported the difference.

    Neither side looks wrong alone, which is why it went unnoticed. This
    compares them, and reads the route half from the source so that a rename
    there fails here instead of being pinned by a literal on this side.
    """
    tools = {t["name"]: t for t in TOOLS}
    reads = _body_keys_the_route_reads("request_approval")

    props = set(tools["haldir_request_approval"]["inputSchema"]["properties"])
    unknown = sorted(props - reads)
    assert not unknown, (
        f"haldir_request_approval declares {unknown}, and POST "
        f"/v1/approvals/request never reads those — the argument is accepted "
        f"and then discarded. The route reads: {sorted(reads)}"
    )
    assert "ttl" in props, (
        "the route's expiry parameter is not declared, so a caller cannot set it"
    )


def test_the_approval_status_tool_accepts_the_name_the_create_call_returns() -> None:
    """`haldir_request_approval` returns `request_id`, so the status tool must
    accept that name — otherwise the caller translates between two names for
    one value.

    `approval_id` is kept as an alias. It was the documented name and it
    *worked*: it is interpolated into the request path, so removing it breaks
    existing callers rather than tidying anything. Found by an independent
    review after an earlier version of this change dropped it outright.
    """
    tools = {t["name"]: t for t in TOOLS}
    props = set(tools["haldir_get_approval_status"]["inputSchema"]["properties"])
    assert "request_id" in props, (
        f"the create call returns `request_id`; the status tool must accept "
        f"it: {sorted(props)}"
    )
    assert "approval_id" in props, (
        "the previous name must keep working — it was not a no-op"
    )


def test_the_approval_route_honours_the_ttl_it_is_given(
    haldir_client, bootstrap_key
) -> None:
    """The other half of the same invariant.

    Renaming the schema alone would leave the route ignoring a
    correctly-named argument — the same silent no-op wearing the right label.
    """
    import hashlib
    import time

    import api
    from haldir_db import get_db

    headers = {"Authorization": f"Bearer {bootstrap_key}"}

    # The session has to belong to the key's tenant or the route answers 401
    # for a reason that has nothing to do with what this test is about, so the
    # tenant is looked up rather than assumed.
    conn = get_db(api.DB_PATH)
    try:
        row = conn.execute(
            "SELECT tenant_id FROM api_keys WHERE key_hash = ?",
            (hashlib.sha256(bootstrap_key.encode()).hexdigest(),),
        ).fetchone()
    finally:
        conn.close()
    tenant = row["tenant_id"]

    # Minted directly rather than over POST /v1/sessions: that route enforces
    # the free tier's one-agent cap, and the shared suite filled it long ago.
    session = api.gate.create_session(
        "ttl-probe", scopes=["read"], ttl=3600, tenant_id=tenant,
    )

    before = time.time()
    r = haldir_client.post(
        "/v1/approvals/request",
        json={
            "session_id": session.session_id,
            "action": "deploy",
            "reason": "ttl is honoured",
            "ttl": 120,
        },
        headers=headers,
    )
    assert r.status_code == 201, r.data

    granted = r.get_json()["expires_at"] - before
    assert 60 <= granted <= 200, (
        f"asked for a 120s TTL and got {granted:.0f}s — the argument is being "
        f"ignored and the 3600s default used instead"
    )
