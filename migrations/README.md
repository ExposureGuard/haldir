# Haldir migrations

Schema changes ship as numbered SQL files in this directory. Every
change to the database — new table, new column, new index, data
backfill — is a migration; nothing else is allowed to mutate schema
in production.

## Writing a new migration

1. Pick the next unused number (`002`, `003`, …).
2. Name the file `<NNN>_<short_description>.sql`, all lowercase, e.g.
   `002_add_proxy_upstreams.sql`.
3. Write PostgreSQL-syntax SQL. The runner rewrites dialect-specific
   bits (`BYTEA` → `BLOB`, `SERIAL PRIMARY KEY` → `INTEGER PRIMARY KEY
   AUTOINCREMENT`) when applied against SQLite.
4. Keep every statement idempotent (`CREATE TABLE IF NOT EXISTS`,
   `CREATE INDEX IF NOT EXISTS`). The runner applies each migration
   exactly once, but idempotency lets operators re-run safely after
   partial failures.
5. **Never edit a migration after it has been applied anywhere.** The
   runner SHA-256s each file at apply time and logs loudly if the
   stored checksum diverges from the file on disk. Create a new
   migration to correct mistakes, don't mutate history.

## Running migrations

```bash
# Apply every pending migration
python -m haldir_migrate up

# Show applied + pending (and warn on checksum drift)
python -m haldir_migrate status

# Verify applied migrations against the files on disk
python -m haldir_migrate verify
```

Set `HALDIR_AUTO_MIGRATE=1` to have `api.py` run `up` at import
time. That's the recommended default in Docker deploys; pair it with
a readiness probe that only goes healthy after the first boot.

## Legacy bootstrap

If Haldir has been running under the old `init_db()` code path, the
tables already exist but `schema_migrations` doesn't. The runner
detects this, creates `schema_migrations`, and marks `001_initial`
as applied **without re-running it** — so upgrading is a no-op from
the DB's perspective. First new migration to land after that runs
normally.
