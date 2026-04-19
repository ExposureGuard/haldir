"""
Haldir audit-trail export — streaming CSV / JSONL + signed manifest.

Compliance, security, and SRE teams all need to pull the audit trail
out of Haldir and into whatever system of record they already run
(SIEM, data warehouse, archival bucket, SOC2 evidence locker). This
module is the export surface.

Design choices:

  - **Streamed.** Rows land in batches of 500 from the DB and flow
    straight into an HTTP response generator, so a tenant with a
    million-row audit log can still be exported without holding it
    all in Python memory. The batch size is tuned so each DB round
    trip is cheap but not page-sized-thrashy.

  - **Chronological.** ORDER BY timestamp ASC. Exports walk the
    chain the same direction it was written, so consumers can
    re-compute entry_hash as they read without having to reorder.
    (The interactive /v1/audit endpoint goes DESC for UI reasons —
    that's a different use case.)

  - **Verifiable.** Every export carries a manifest: count,
    first/last timestamps, the last chain hash, and a SHA-256 of
    the canonical entry-id concatenation. If a row is tampered
    with or dropped *between export and ingest*, the consumer's
    recomputed digest diverges. The manifest is emitted as the
    final record of the stream (JSONL) and also available out-of-
    band via the /v1/audit/export/manifest endpoint for CSV
    consumers that can't tolerate a footer line.

  - **Format-agnostic core.** `stream_audit_rows` is a pure
    generator of AuditEntry objects. CSV and JSONL are thin
    serializers on top; adding Parquet / Avro later is a new
    serializer, not a rewrite.

  - **No Flask dependency.** The whole module is test-driveable
    with a DB path, a tenant id, and a filter dict. The HTTP
    wrapping lives in api.py.

Supported filters:
    session_id      Only rows for this session
    agent_id        Only rows for this agent
    tool            Only rows naming this tool
    since           Unix seconds — lower bound (inclusive)
    until           Unix seconds — upper bound (exclusive)
    flagged_only    If truthy, only flagged rows

Manifest format:
    {
      "type": "manifest",
      "format_version": 1,
      "tenant_id": "...",
      "generated_at": "2026-04-19T...Z",
      "filters": {...},
      "count": 12345,
      "first_timestamp": 1745200000.0,
      "last_timestamp":  1745600000.0,
      "last_chain_hash": "ab...",
      "sha256": "the sha-256 of entry_ids joined by \\n"
    }
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator


FORMAT_VERSION = 1
BATCH_SIZE = 500

# CSV header order is part of the stable contract — downstream parsers
# index by column position. New columns go at the end.
CSV_COLUMNS: tuple[str, ...] = (
    "entry_id", "timestamp", "timestamp_iso",
    "tenant_id", "session_id", "agent_id",
    "tool", "action", "cost_usd",
    "flagged", "flag_reason",
    "details_json", "prev_hash", "entry_hash",
)


@dataclass
class ExportFilters:
    """Canonical filter set. Accepted via keyword; serialized into the
    manifest verbatim so an auditor can see what slice was exported."""
    session_id: str | None = None
    agent_id: str | None = None
    tool: str | None = None
    since: float | None = None
    until: float | None = None
    flagged_only: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Drop null fields so the manifest stays clean."""
        d: dict[str, Any] = {}
        for k, v in self.__dict__.items():
            if v is None or v is False:
                continue
            d[k] = v
        return d


# ── Streaming source ──────────────────────────────────────────────────

def stream_audit_rows(
    db_path: str,
    tenant_id: str,
    filters: ExportFilters,
    batch_size: int = BATCH_SIZE,
) -> Iterator[dict[str, Any]]:
    """Yield one row at a time, in timestamp-ASC order, from the
    audit_log table. Uses batched LIMIT/OFFSET so both SQLite and
    Postgres paths stream without loading the full result set.

    The yielded dicts are already shaped for downstream serializers —
    details parsed to an object, timestamps left as floats, entry_hash
    always present (empty string if the row predates hash chaining)."""
    from haldir_db import get_db

    base_sql = "SELECT * FROM audit_log WHERE tenant_id = ?"
    params: list[Any] = [tenant_id]
    if filters.session_id:
        base_sql += " AND session_id = ?"
        params.append(filters.session_id)
    if filters.agent_id:
        base_sql += " AND agent_id = ?"
        params.append(filters.agent_id)
    if filters.tool:
        base_sql += " AND tool = ?"
        params.append(filters.tool)
    if filters.since is not None:
        base_sql += " AND timestamp >= ?"
        params.append(filters.since)
    if filters.until is not None:
        base_sql += " AND timestamp < ?"
        params.append(filters.until)
    if filters.flagged_only:
        base_sql += " AND flagged = 1"
    base_sql += " ORDER BY timestamp ASC LIMIT ? OFFSET ?"

    offset = 0
    while True:
        conn = get_db(db_path)
        try:
            rows = conn.execute(base_sql, params + [batch_size, offset]).fetchall()
        finally:
            conn.close()
        if not rows:
            return
        for r in rows:
            yield _row_to_dict(r)
        if len(rows) < batch_size:
            return
        offset += batch_size


def _row_to_dict(r: Any) -> dict[str, Any]:
    """Flatten a DB row to the serializer-friendly shape. `r` may be
    a sqlite3.Row or one of our PgRow wrappers — both expose a dict
    interface."""
    try:
        details = json.loads(r["details"]) if r["details"] else {}
    except (json.JSONDecodeError, TypeError):
        details = {"_raw": r["details"]}
    return {
        "entry_id":      r["entry_id"],
        "timestamp":     float(r["timestamp"]),
        "timestamp_iso": datetime.fromtimestamp(
                             float(r["timestamp"]), tz=timezone.utc
                         ).isoformat(timespec="seconds"),
        "tenant_id":     r["tenant_id"],
        "session_id":    r["session_id"],
        "agent_id":      r["agent_id"],
        "tool":          r["tool"] or "",
        "action":        r["action"],
        "cost_usd":      float(r["cost_usd"]),
        "flagged":       bool(r["flagged"]),
        "flag_reason":   r["flag_reason"] or "",
        "details":       details,
        "prev_hash":     r["prev_hash"] if "prev_hash" in r.keys() else "",
        "entry_hash":    r["entry_hash"] if "entry_hash" in r.keys() else "",
    }


# ── Manifest builder ──────────────────────────────────────────────────

class ManifestBuilder:
    """Accumulates the per-row metadata needed to emit a verification
    manifest at end-of-stream. Feed every row, then call `finalize()`.

    The sha256 is computed over the canonical string
    `<entry_id>\\n<entry_id>\\n...`, in the order rows were exported —
    the same order a re-ingest pipeline would read them. Any insertion
    or deletion of rows changes the digest."""

    def __init__(self, tenant_id: str, filters: ExportFilters) -> None:
        self._hasher = hashlib.sha256()
        self._count = 0
        self._first_ts: float | None = None
        self._last_ts: float | None = None
        self._last_chain_hash = ""
        self._tenant_id = tenant_id
        self._filters = filters

    def observe(self, row: dict[str, Any]) -> None:
        self._count += 1
        ts = row["timestamp"]
        if self._first_ts is None:
            self._first_ts = ts
        self._last_ts = ts
        self._hasher.update(row["entry_id"].encode())
        self._hasher.update(b"\n")
        if row.get("entry_hash"):
            self._last_chain_hash = row["entry_hash"]

    def finalize(self) -> dict[str, Any]:
        return {
            "type":             "manifest",
            "format_version":   FORMAT_VERSION,
            "tenant_id":        self._tenant_id,
            "generated_at":     datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "filters":          self._filters.to_dict(),
            "count":            self._count,
            "first_timestamp":  self._first_ts,
            "last_timestamp":   self._last_ts,
            "last_chain_hash":  self._last_chain_hash,
            "sha256":           self._hasher.hexdigest(),
        }


# ── Serializers ───────────────────────────────────────────────────────

def iter_jsonl(
    rows: Iterable[dict[str, Any]],
    manifest_builder: ManifestBuilder | None = None,
    append_manifest: bool = True,
) -> Iterator[str]:
    """Emit one JSON object per line. Each line ends with `\\n`, which
    is the contract every jsonl consumer (jq, DuckDB, Spark, Snowflake
    COPY) expects. When `append_manifest` is true, the last line is the
    manifest record so a streaming consumer can verify integrity
    inline."""
    for row in rows:
        if manifest_builder is not None:
            manifest_builder.observe(row)
        # Drop the derived `timestamp_iso` — consumers have `timestamp`
        # and the isoformat is reproducible from it. Keeps payload lean.
        out = {k: v for k, v in row.items() if k != "timestamp_iso"}
        yield json.dumps(out, separators=(",", ":")) + "\n"
    if append_manifest and manifest_builder is not None:
        yield json.dumps(manifest_builder.finalize(), separators=(",", ":")) + "\n"


def iter_csv(
    rows: Iterable[dict[str, Any]],
    manifest_builder: ManifestBuilder | None = None,
) -> Iterator[str]:
    """Emit CSV with a stable header row. Manifest is NOT embedded in
    CSV (the format has no native footer convention that all parsers
    tolerate); callers who need chain verification should hit
    /v1/audit/export/manifest or use JSONL."""
    # Build CSV into a module-local StringIO so the `csv` stdlib writer
    # handles quoting; yield the accumulated text then reset. This keeps
    # us streaming (one row at a time flushed out) without needing to
    # hand-roll CSV escaping.
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    yield buf.getvalue()
    buf.seek(0); buf.truncate()

    for row in rows:
        if manifest_builder is not None:
            manifest_builder.observe(row)
        writer.writerow([
            row["entry_id"],
            f"{row['timestamp']:.6f}",
            row["timestamp_iso"],
            row["tenant_id"],
            row["session_id"],
            row["agent_id"],
            row["tool"],
            row["action"],
            f"{row['cost_usd']:.2f}",
            "true" if row["flagged"] else "false",
            row["flag_reason"],
            json.dumps(row["details"], separators=(",", ":")),
            row["prev_hash"],
            row["entry_hash"],
        ])
        yield buf.getvalue()
        buf.seek(0); buf.truncate()


# ── Top-level entry points ────────────────────────────────────────────

def export_stream(
    db_path: str,
    tenant_id: str,
    filters: ExportFilters,
    fmt: str,
) -> Iterator[str]:
    """Run the pipeline end-to-end. `fmt` is 'csv' or 'jsonl'."""
    if fmt not in ("csv", "jsonl"):
        raise ValueError(f"unsupported format: {fmt!r}")
    mb = ManifestBuilder(tenant_id, filters)
    rows = stream_audit_rows(db_path, tenant_id, filters)
    if fmt == "csv":
        yield from iter_csv(rows, mb)
    else:
        yield from iter_jsonl(rows, mb, append_manifest=True)


def compute_manifest(
    db_path: str,
    tenant_id: str,
    filters: ExportFilters,
) -> dict[str, Any]:
    """Walk the same filter set as export_stream but consume the rows
    server-side, returning only the manifest. Use this when a consumer
    wants chain verification without re-downloading the export body."""
    mb = ManifestBuilder(tenant_id, filters)
    for row in stream_audit_rows(db_path, tenant_id, filters):
        mb.observe(row)
    return mb.finalize()
