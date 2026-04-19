"""
Tests for haldir_export — the audit-trail export pipeline.

Scope:
  - CSV and JSONL serializers produce the documented shapes
  - Streamed output preserves chronological order (timestamp ASC)
  - Manifest correctness: count + first/last timestamps + last_chain_hash
  - SHA-256 of the entry_id sequence matches client-side recompute
  - Filter parameters (session_id / agent_id / tool / since / until /
    flagged) narrow results correctly
  - End-to-end via /v1/audit/export and /v1/audit/export/manifest

Run: python -m pytest tests/test_audit_export.py -v
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import api  # noqa: E402
import haldir_export  # noqa: E402


@pytest.fixture(autouse=True)
def _lift_agent_cap(monkeypatch) -> None:
    """The bootstrap key lives on tier=free, which caps agents at 1 per
    tenant. This suite creates several distinct agent_ids to exercise
    filter narrowing, so lift the cap for the duration of each test."""
    import copy
    patched = copy.deepcopy(api.TIER_LIMITS)
    patched["free"]["agents"] = 999
    monkeypatch.setattr(api, "TIER_LIMITS", patched)
from haldir_export import (  # noqa: E402
    CSV_COLUMNS,
    ExportFilters,
    ManifestBuilder,
    compute_manifest,
    export_stream,
    iter_csv,
    iter_jsonl,
)


# ── Helpers: seed some audit rows for the bootstrap tenant ────────────

def _seed_rows(haldir_client, bootstrap_key, count: int = 5,
               session_id: str = "ses_test_export",
               agent_id: str = "agent-export") -> list[str]:
    """Mint a session then log `count` audit rows. Returns the entry_ids
    in the order they were logged (= the order export should yield)."""
    s = haldir_client.post(
        "/v1/sessions",
        json={"agent_id": agent_id, "scopes": ["read", "execute"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    sid = s.get_json()["session_id"]

    ids: list[str] = []
    for i in range(count):
        r = haldir_client.post(
            "/v1/audit",
            json={
                "session_id": sid,
                "tool": "stripe" if i % 2 == 0 else "slack",
                "action": f"call-{i}",
                "cost_usd": 0.10 * i,
                "details": {"idx": i},
            },
            headers={"Authorization": f"Bearer {bootstrap_key}"},
        )
        ids.append(r.get_json()["entry_id"])
    return ids


def _current_tenant(bootstrap_key: str) -> str:
    """Look up the tenant_id the bootstrap key writes under."""
    kh = hashlib.sha256(bootstrap_key.encode()).hexdigest()
    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    row = conn.execute(
        "SELECT tenant_id FROM api_keys WHERE key_hash = ?", (kh,),
    ).fetchone()
    conn.close()
    return row["tenant_id"]


# ── Manifest builder unit tests ───────────────────────────────────────

def test_manifest_builder_counts_and_hashes() -> None:
    mb = ManifestBuilder(tenant_id="t1", filters=ExportFilters())
    mb.observe({"entry_id": "a", "timestamp": 1.0, "entry_hash": "h1"})
    mb.observe({"entry_id": "b", "timestamp": 2.0, "entry_hash": "h2"})
    out = mb.finalize()
    assert out["count"] == 2
    assert out["first_timestamp"] == 1.0
    assert out["last_timestamp"] == 2.0
    assert out["last_chain_hash"] == "h2"
    expected = hashlib.sha256(b"a\nb\n").hexdigest()
    assert out["sha256"] == expected


def test_manifest_builder_handles_empty() -> None:
    mb = ManifestBuilder(tenant_id="t", filters=ExportFilters())
    out = mb.finalize()
    assert out["count"] == 0
    assert out["first_timestamp"] is None
    assert out["last_timestamp"] is None
    assert out["last_chain_hash"] == ""
    assert out["sha256"] == hashlib.sha256(b"").hexdigest()


def test_manifest_drops_null_filters() -> None:
    """Empty / false filters shouldn't bloat the manifest output —
    auditors reading the JSON want only what actually applied."""
    f = ExportFilters(session_id="ses_1", flagged_only=False, agent_id=None)
    assert f.to_dict() == {"session_id": "ses_1"}


# ── Serializer shape ──────────────────────────────────────────────────

def test_jsonl_emits_line_per_row_then_manifest() -> None:
    rows = [
        {"entry_id": "a", "timestamp": 1.0, "timestamp_iso": "2026-01-01T00:00:01+00:00",
         "tenant_id": "t", "session_id": "s", "agent_id": "ag", "tool": "x",
         "action": "run", "cost_usd": 0.0, "flagged": False, "flag_reason": "",
         "details": {}, "prev_hash": "", "entry_hash": "h1"},
        {"entry_id": "b", "timestamp": 2.0, "timestamp_iso": "2026-01-01T00:00:02+00:00",
         "tenant_id": "t", "session_id": "s", "agent_id": "ag", "tool": "x",
         "action": "run", "cost_usd": 0.0, "flagged": False, "flag_reason": "",
         "details": {}, "prev_hash": "h1", "entry_hash": "h2"},
    ]
    mb = ManifestBuilder("t", ExportFilters())
    lines = list(iter_jsonl(rows, mb))
    assert len(lines) == 3  # 2 rows + 1 manifest
    parsed = [json.loads(L) for L in lines]
    assert parsed[0]["entry_id"] == "a"
    assert parsed[1]["entry_id"] == "b"
    assert parsed[2]["type"] == "manifest"
    assert parsed[2]["count"] == 2
    # timestamp_iso stripped from body rows (derivable from timestamp).
    assert "timestamp_iso" not in parsed[0]


def test_csv_emits_header_then_rows() -> None:
    rows = [{
        "entry_id": "a", "timestamp": 1.5, "timestamp_iso": "2026-01-01T00:00:01+00:00",
        "tenant_id": "t", "session_id": "s", "agent_id": "ag", "tool": "x",
        "action": "run", "cost_usd": 0.55, "flagged": True, "flag_reason": "spike",
        "details": {"k": "v"}, "prev_hash": "p", "entry_hash": "h",
    }]
    mb = ManifestBuilder("t", ExportFilters())
    body = "".join(iter_csv(rows, mb))
    reader = csv.reader(io.StringIO(body))
    header = next(reader)
    assert header == list(CSV_COLUMNS)
    data_row = next(reader)
    assert data_row[0] == "a"
    assert data_row[8] == "0.55"          # cost_usd formatted
    assert data_row[9] == "true"          # flagged
    assert data_row[11] == '{"k":"v"}'    # details as compact JSON
    # No manifest footer in CSV.
    assert next(reader, None) is None


def test_unsupported_format_raises() -> None:
    gen = export_stream("/tmp/does_not_matter.db", "t",
                        ExportFilters(), fmt="parquet")
    with pytest.raises(ValueError, match="parquet"):
        next(gen)


# ── End-to-end through the streaming source ──────────────────────────

def test_stream_rows_yields_ascending_timestamps(haldir_client, bootstrap_key) -> None:
    ids = _seed_rows(haldir_client, bootstrap_key, count=4,
                     session_id="ses_asc", agent_id="agent-asc")
    tenant = _current_tenant(bootstrap_key)
    rows = list(haldir_export.stream_audit_rows(
        api.DB_PATH, tenant, ExportFilters(agent_id="agent-asc"),
    ))
    # At least the rows we seeded are present (other tests may seed
    # more under the same tenant).
    assert len(rows) >= 4
    # Timestamps monotonic non-decreasing.
    for i in range(1, len(rows)):
        assert rows[i]["timestamp"] >= rows[i - 1]["timestamp"]
    # The seeded ids should appear in the yielded sequence.
    seen = [r["entry_id"] for r in rows]
    for entry_id in ids:
        assert entry_id in seen


def test_filter_by_session_id_narrows(haldir_client, bootstrap_key) -> None:
    ids = _seed_rows(haldir_client, bootstrap_key, count=3,
                     session_id="ses_narrow", agent_id="agent-narrow")
    tenant = _current_tenant(bootstrap_key)
    # Get the actual session_id the seed created (not the fake one).
    rows = list(haldir_export.stream_audit_rows(
        api.DB_PATH, tenant, ExportFilters(agent_id="agent-narrow"),
    ))
    session_ids = {r["session_id"] for r in rows}
    assert len(session_ids) >= 1

    # Pick any seen session_id, refilter.
    target = next(iter(session_ids))
    narrowed = list(haldir_export.stream_audit_rows(
        api.DB_PATH, tenant,
        ExportFilters(session_id=target, agent_id="agent-narrow"),
    ))
    assert narrowed
    assert all(r["session_id"] == target for r in narrowed)


# ── End-to-end through the Flask routes ──────────────────────────────

def test_export_endpoint_jsonl_streams_rows_and_manifest(haldir_client, bootstrap_key) -> None:
    _seed_rows(haldir_client, bootstrap_key, count=3, agent_id="agent-e2e-jsonl")
    r = haldir_client.get(
        "/v1/audit/export?format=jsonl&agent_id=agent-e2e-jsonl",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    assert r.mimetype == "application/x-ndjson"
    assert r.headers["X-Haldir-Export-Manifest"] == "embedded-final-line"
    assert "attachment" in r.headers["Content-Disposition"]

    lines = [L for L in r.data.decode().split("\n") if L]
    parsed = [json.loads(L) for L in lines]
    # The last line must be the manifest.
    assert parsed[-1]["type"] == "manifest"
    assert parsed[-1]["count"] == len(parsed) - 1
    # Count + sha256 are internally consistent.
    body_ids = [p["entry_id"] for p in parsed[:-1]]
    expected_sha = hashlib.sha256(
        ("\n".join(body_ids) + "\n").encode() if body_ids else b""
    ).hexdigest()
    assert parsed[-1]["sha256"] == expected_sha


def test_export_endpoint_csv_has_stable_header(haldir_client, bootstrap_key) -> None:
    _seed_rows(haldir_client, bootstrap_key, count=2, agent_id="agent-e2e-csv")
    r = haldir_client.get(
        "/v1/audit/export?format=csv&agent_id=agent-e2e-csv",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    assert r.headers["X-Haldir-Export-Manifest"] == "out-of-band"
    body = r.data.decode()
    reader = csv.reader(io.StringIO(body))
    header = next(reader)
    assert header == list(CSV_COLUMNS)
    rows = list(reader)
    assert len(rows) >= 2


def test_export_endpoint_rejects_bad_format(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(
        "/v1/audit/export?format=parquet",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400
    assert r.get_json()["code"] == "invalid_format"


def test_manifest_endpoint_matches_embedded_manifest(haldir_client, bootstrap_key) -> None:
    """/v1/audit/export/manifest and the embedded JSONL trailer must
    agree on count + sha256 + last_chain_hash for the same filter set.
    This is the contract an out-of-band verifier relies on."""
    _seed_rows(haldir_client, bootstrap_key, count=3, agent_id="agent-manifest")

    jr = haldir_client.get(
        "/v1/audit/export?format=jsonl&agent_id=agent-manifest",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    lines = [L for L in jr.data.decode().split("\n") if L]
    embedded = json.loads(lines[-1])

    mr = haldir_client.get(
        "/v1/audit/export/manifest?agent_id=agent-manifest",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert mr.status_code == 200
    standalone = mr.get_json()

    assert embedded["count"] == standalone["count"]
    assert embedded["sha256"] == standalone["sha256"]
    assert embedded["last_chain_hash"] == standalone["last_chain_hash"]


def test_export_returns_empty_for_no_matches(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(
        "/v1/audit/export?format=jsonl&agent_id=nonexistent-agent",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    lines = [L for L in r.data.decode().split("\n") if L]
    # Only the manifest line.
    assert len(lines) == 1
    manifest = json.loads(lines[0])
    assert manifest["type"] == "manifest"
    assert manifest["count"] == 0


def test_export_requires_auth(haldir_client) -> None:
    r = haldir_client.get("/v1/audit/export")
    assert r.status_code in (401, 403)


def test_manifest_endpoint_requires_auth(haldir_client) -> None:
    r = haldir_client.get("/v1/audit/export/manifest")
    assert r.status_code in (401, 403)


# ── ISO-8601 `since` / `until` parsing ───────────────────────────────

def test_export_accepts_iso_timestamps(haldir_client, bootstrap_key) -> None:
    """since/until should accept both unix seconds and ISO 8601 so
    humans + machines both work. An ISO string far in the future should
    return zero rows (and a valid manifest)."""
    r = haldir_client.get(
        "/v1/audit/export?format=jsonl&since=2099-01-01T00:00:00Z",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    lines = [L for L in r.data.decode().split("\n") if L]
    manifest = json.loads(lines[-1])
    assert manifest["count"] == 0
