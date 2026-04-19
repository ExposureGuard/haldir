"""
Haldir schema migrations — forward-only, checksum-verified, idempotent.

Why a homegrown migrator instead of Alembic:

  - Alembic is ~20 dependencies deep and requires a config module, an
    env.py, a target metadata import, and opinions about autogenerate.
    Haldir needs "run these .sql files in order, once each." Five
    hundred lines of Alembic config to express five hundred lines of
    SQL is a bad trade.
  - A homegrown tool under our control lets us ship dialect translation
    (Postgres → SQLite) in a single spot and version the checksum
    policy we actually want.
  - Every primitive here is stdlib. Zero new wheels in the Docker image.

What it does:

  - Discovers NNN_*.sql files in `migrations/` and applies any not yet
    recorded in the `schema_migrations` table, in numeric order.
  - Applies each migration in a transaction.
  - Records {version, name, checksum, applied_at} after each success.
  - Verifies checksums on boot: if an applied migration's file has
    been edited on disk, a WARNING is logged so operators catch silent
    drift before it corrupts production.
  - Bootstraps existing deployments: if the tables already exist but
    `schema_migrations` doesn't, the runner marks the initial
    migration as applied without re-running it.
  - Translates Postgres syntax to SQLite (BYTEA → BLOB, SERIAL PRIMARY
    KEY → INTEGER PRIMARY KEY AUTOINCREMENT) so one canonical source
    supports both paths.

What it intentionally doesn't do:

  - Rollbacks. Most production teams don't use down-migrations; the
    revert is "write a new forward migration that undoes the change."
    Adding .down.sql support later is cheap; adding it prematurely is
    complexity we don't need.
  - Autogenerate. Schema changes are reviewed by humans; we want the
    human to write the DDL, not have it inferred.
  - Locking. The runner relies on operators running it once per
    deploy (or HALDIR_AUTO_MIGRATE at boot under a gunicorn
    single-leader pattern). A shared-lock table is the natural
    next step once Haldir runs on multiple hosts.

CLI:
    python -m haldir_migrate up          apply pending migrations
    python -m haldir_migrate status      list applied + pending
    python -m haldir_migrate verify      check checksums for drift
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any

from haldir_logging import get_logger

log = get_logger("haldir.migrate")

# Where migration files live by default. Override with HALDIR_MIGRATIONS_DIR
# in tests or unusual deployments.
_DEFAULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migrations")

# Filename convention: NNN_short_name.sql. Number is the version key.
_FILENAME_RE = re.compile(r"^(\d+)_([a-z0-9_]+)\.sql$")

# One table to rule them all. Created on first run if absent.
_SCHEMA_MIGRATIONS_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    checksum   TEXT    NOT NULL,
    applied_at REAL    NOT NULL
)
"""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: str
    checksum: str
    body: str


# ── Discovery ──────────────────────────────────────────────────────────

def _migrations_dir() -> str:
    return os.environ.get("HALDIR_MIGRATIONS_DIR", _DEFAULT_DIR)


def discover(directory: str | None = None) -> list[Migration]:
    """Return every migration in `directory`, sorted by version ASC.

    Raises `ValueError` on duplicate version numbers — that's almost
    always a rebase accident and silently picking one would be a
    correctness bug."""
    d = directory or _migrations_dir()
    if not os.path.isdir(d):
        return []
    out: dict[int, Migration] = {}
    for fname in os.listdir(d):
        m = _FILENAME_RE.match(fname)
        if not m:
            continue
        version = int(m.group(1))
        name = m.group(2)
        path = os.path.join(d, fname)
        with open(path, "rb") as f:
            body_bytes = f.read()
        checksum = hashlib.sha256(body_bytes).hexdigest()
        if version in out:
            raise ValueError(
                f"duplicate migration version {version}: "
                f"{out[version].path} vs {path}"
            )
        out[version] = Migration(
            version=version, name=name, path=path,
            checksum=checksum, body=body_bytes.decode("utf-8"),
        )
    return sorted(out.values(), key=lambda m: m.version)


# ── Dialect translation ────────────────────────────────────────────────

def _is_sqlite(conn: Any) -> bool:
    """Inspect the live connection to decide whether dialect rewriting
    is needed. We check for psycopg2 attributes rather than sqlite3
    so the Pg connection wrapper (haldir_db.PgConnectionWrapper) also
    gets classified correctly."""
    # Our PgConnectionWrapper stores the raw psycopg2 conn as ._conn.
    if hasattr(conn, "_conn"):
        return False
    import sqlite3
    return isinstance(conn, sqlite3.Connection)


def _translate_for_sqlite(sql: str) -> str:
    """Rewrite the small set of Postgres-only bits we use into their
    SQLite equivalents. Kept minimal on purpose — anything more
    sophisticated than this handful of substitutions indicates the
    migration should be dialect-specific (and we'd introduce
    .postgres.sql / .sqlite.sql naming at that point)."""
    s = sql
    s = s.replace("BYTEA", "BLOB")
    s = s.replace("DOUBLE PRECISION", "REAL")
    # SERIAL PRIMARY KEY → INTEGER PRIMARY KEY AUTOINCREMENT.
    s = re.sub(
        r"\bSERIAL\s+PRIMARY\s+KEY\b",
        "INTEGER PRIMARY KEY AUTOINCREMENT",
        s, flags=re.IGNORECASE,
    )
    return s


# ── State-table helpers ────────────────────────────────────────────────

def _ensure_state_table(conn: Any) -> None:
    conn.execute(_SCHEMA_MIGRATIONS_DDL)
    conn.commit()


def _table_exists(conn: Any, name: str) -> bool:
    """Dialect-neutral existence check. SQLite has sqlite_master;
    Postgres has information_schema."""
    if _is_sqlite(conn):
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = %s", (name,),
        ).fetchone()
    return row is not None


def _applied_versions(conn: Any) -> dict[int, dict[str, Any]]:
    cur = conn.execute(
        "SELECT version, name, checksum, applied_at FROM schema_migrations"
    )
    return {
        row["version"]: {
            "version":   row["version"],
            "name":      row["name"],
            "checksum":  row["checksum"],
            "applied_at": row["applied_at"],
        }
        for row in cur.fetchall()
    }


def _record(conn: Any, m: Migration) -> None:
    conn.execute(
        "INSERT INTO schema_migrations (version, name, checksum, applied_at) "
        "VALUES (?, ?, ?, ?)",
        (m.version, m.name, m.checksum, time.time()),
    )


# ── Public API ─────────────────────────────────────────────────────────

def apply_pending(
    db_path: str,
    directory: str | None = None,
    log_drift: bool = True,
) -> dict[str, Any]:
    """Apply every discovered migration not already recorded. Returns a
    summary dict: {applied: [versions], skipped: [versions],
    bootstrapped: bool, drift: [versions]}.

    - `applied`     migrations run during this call
    - `skipped`     already-applied, no-op
    - `bootstrapped` True if schema_migrations was created fresh and
                     an existing schema was adopted as v1
    - `drift`       applied migrations whose file on disk no longer
                     matches the checksum we recorded at apply time
    """
    from haldir_db import get_db

    migrations = discover(directory)
    summary: dict[str, Any] = {
        "applied":      [],
        "skipped":      [],
        "bootstrapped": False,
        "drift":        [],
    }
    if not migrations:
        log.warning("no migration files found", extra={
            "directory": directory or _migrations_dir(),
        })
        return summary

    conn = get_db(db_path)
    try:
        # Legacy bootstrap: tables already exist, but we've never
        # recorded a migration. Create schema_migrations fresh and
        # record 001 as applied without re-running its body.
        had_state = _table_exists(conn, "schema_migrations")
        _ensure_state_table(conn)
        if (not had_state) and _table_exists(conn, "api_keys"):
            first = migrations[0]
            _record(conn, first)
            conn.commit()
            summary["bootstrapped"] = True
            log.info(
                "migration bootstrap: adopted existing schema as v1",
                extra={"version": first.version, "migration_name": first.name},
            )

        applied = _applied_versions(conn)

        # Apply everything still pending, in order.
        for m in migrations:
            if m.version in applied:
                recorded = applied[m.version]
                if log_drift and recorded["checksum"] != m.checksum:
                    summary["drift"].append(m.version)
                    log.warning(
                        "applied migration file has diverged from its recorded checksum",
                        extra={
                            "version":          m.version,
                            "migration_name":   m.name,
                            "recorded_sha256":  recorded["checksum"],
                            "on_disk_sha256":   m.checksum,
                        },
                    )
                summary["skipped"].append(m.version)
                continue

            body = m.body
            if _is_sqlite(conn):
                body = _translate_for_sqlite(body)

            log.info("applying migration", extra={
                "version": m.version, "migration_name": m.name,
            })
            try:
                conn.executescript(body) if hasattr(conn, "executescript") \
                    else _exec_multi(conn, body)
                _record(conn, m)
                conn.commit()
            except Exception:
                conn.rollback() if hasattr(conn, "rollback") else None
                log.exception("migration failed", extra={
                    "version": m.version, "migration_name": m.name,
                })
                raise
            summary["applied"].append(m.version)
    finally:
        conn.close()
    return summary


def _exec_multi(conn: Any, sql: str) -> None:
    """Postgres path: split the migration body at semicolons and run
    each statement. SQLite uses conn.executescript() directly (path in
    apply_pending). Split is naive — it assumes no semicolons inside
    string literals, which is true for every migration we ship."""
    for stmt in (s.strip() for s in sql.split(";")):
        if stmt:
            conn.execute(stmt)


def status(db_path: str, directory: str | None = None) -> dict[str, Any]:
    """Read-only snapshot — what's applied, what's pending, what's
    drifted. Used by the CLI and useful from tests."""
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        migrations = discover(directory)
        if not _table_exists(conn, "schema_migrations"):
            return {
                "applied": [],
                "pending": [{"version": m.version, "name": m.name}
                            for m in migrations],
                "drift":   [],
            }
        applied = _applied_versions(conn)
        pending = [m for m in migrations if m.version not in applied]
        drift = []
        for m in migrations:
            rec = applied.get(m.version)
            if rec and rec["checksum"] != m.checksum:
                drift.append(m.version)
        return {
            "applied": [
                {"version": v, "name": r["name"], "applied_at": r["applied_at"]}
                for v, r in sorted(applied.items())
            ],
            "pending": [{"version": m.version, "name": m.name} for m in pending],
            "drift":   drift,
        }
    finally:
        conn.close()


# ── CLI ────────────────────────────────────────────────────────────────

def _cli_up(db_path: str) -> int:
    summary = apply_pending(db_path)
    print(f"bootstrapped: {summary['bootstrapped']}")
    print(f"applied:      {summary['applied']}")
    print(f"skipped:      {len(summary['skipped'])} already-applied")
    if summary["drift"]:
        print(f"drift:        {summary['drift']}  ← re-review these files")
    return 0


def _cli_status(db_path: str) -> int:
    s = status(db_path)
    if s["applied"]:
        print("applied:")
        for a in s["applied"]:
            print(f"  {a['version']:03d}  {a['name']}")
    else:
        print("applied: (none)")
    if s["pending"]:
        print("pending:")
        for p in s["pending"]:
            print(f"  {p['version']:03d}  {p['name']}")
    else:
        print("pending: (none)")
    if s["drift"]:
        print(f"drift:    {s['drift']}  ← files edited after apply")
    return 0


def _cli_verify(db_path: str) -> int:
    s = status(db_path)
    if s["drift"]:
        print(f"DRIFT DETECTED: versions {s['drift']}")
        return 2
    print("ok — all applied migrations match their files on disk")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("up", "status", "verify"))
    p.add_argument("--db-path", default=None,
                   help="Override HALDIR_DB_PATH / DATABASE_URL (sqlite path)")
    args = p.parse_args()

    db_path = args.db_path or os.environ.get("HALDIR_DB_PATH") or "haldir.db"

    if args.command == "up":
        return _cli_up(db_path)
    if args.command == "status":
        return _cli_status(db_path)
    if args.command == "verify":
        return _cli_verify(db_path)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
