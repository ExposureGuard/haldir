"""
Haldir structured logging.

Emits one JSON document per log record, enriched automatically with the
request-scoped identifiers every observability pipeline needs:

    {
      "ts":         "2026-04-18T21:04:55.812Z",
      "level":      "INFO",
      "logger":     "haldir.api",
      "msg":        "session created",
      "request_id": "7c1e2f...",
      "tenant_id":  "acme",
      "status":     201,
      "duration_ms": 42,
      ...
    }

Design choices:

  - Built on stdlib `logging` so third-party loggers (Flask, werkzeug,
    stripe, httpx) flow through the same formatter without glue code.

  - When called from inside a Flask request, reads `g.request_id` and
    `request.tenant_id` automatically — callers never have to thread
    those through. Outside a request, those fields are simply omitted.

  - JSON-by-default but swap-able with `HALDIR_LOG_JSON=0` for
    human-readable output during local development.

  - Respects `HALDIR_LOG_LEVEL` (INFO by default). `HALDIR_LOG_SILENT=1`
    silences everything for test runs that only care about assertions.

Usage:

    from haldir_logging import get_logger, configure_logging

    configure_logging()        # once at startup
    log = get_logger("haldir.api")

    log.info("session created", extra={"session_id": sid, "agent_id": aid})
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import sys
from typing import Any


# ── Standard LogRecord attributes ────────────────────────────────────────
#
# Anything on a LogRecord that isn't in this set is surfaced as an
# extra field in the JSON body. That's how callers pass per-record
# enrichment via `log.info("...", extra={"agent_id": "..."})`.
_STANDARD_ATTRS = frozenset({
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "message", "module",
    "msecs", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName", "taskName",
})


def _flask_context() -> dict[str, Any]:
    """Pull request-scoped identifiers off Flask's `g` / `request` if we
    are inside a request, otherwise return an empty dict.

    Imported lazily so `haldir_logging` remains importable in contexts
    that don't have Flask installed (SDK, CLI, tests)."""
    try:
        from flask import g, request, has_request_context
    except Exception:
        return {}
    if not has_request_context():
        return {}
    ctx: dict[str, Any] = {}
    rid = getattr(g, "request_id", None)
    if rid:
        ctx["request_id"] = rid
    tenant = getattr(request, "tenant_id", None)
    if tenant:
        ctx["tenant_id"] = tenant
    return ctx


class JsonFormatter(logging.Formatter):
    """Render every record as a single-line JSON document."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            # ISO-8601 with millisecond precision, UTC. Parseable by every
            # mainstream log aggregator (Datadog, Loki, Splunk, CloudWatch).
            "ts": _dt.datetime.fromtimestamp(
                record.created, tz=_dt.timezone.utc,
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # Flask request context — merged first so explicit extras can
        # override them if a caller really needs to.
        payload.update(_flask_context())

        # Surface any user-supplied fields from `extra={}`.
        for attr, value in record.__dict__.items():
            if attr in _STANDARD_ATTRS or attr.startswith("_"):
                continue
            # Avoid leaking exception text here; it's added below.
            if attr in ("message",):
                continue
            if attr in payload:
                # Caller-provided takes precedence over context defaults.
                pass
            payload[attr] = value

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        try:
            return json.dumps(payload, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            # Last-ditch: if a value refuses to serialize, coerce and
            # retry. We prefer a slightly degraded log line over a lost
            # log line.
            return json.dumps(
                {k: str(v) for k, v in payload.items()},
                ensure_ascii=False,
            )


class TextFormatter(logging.Formatter):
    """Human-readable formatter for local dev (HALDIR_LOG_JSON=0)."""

    def format(self, record: logging.LogRecord) -> str:
        ts = _dt.datetime.fromtimestamp(
            record.created, tz=_dt.timezone.utc,
        ).strftime("%H:%M:%S")
        ctx = _flask_context()
        extras = {
            k: v for k, v in record.__dict__.items()
            if k not in _STANDARD_ATTRS and not k.startswith("_") and k != "message"
        }
        extras.update(ctx)
        tail = " ".join(f"{k}={v}" for k, v in extras.items()) if extras else ""
        line = f"{ts} {record.levelname:<5} {record.name} {record.getMessage()}"
        return f"{line}  {tail}" if tail else line


_CONFIGURED = False


def configure_logging(level: str | None = None, json_output: bool | None = None) -> None:
    """Install Haldir's formatter on the root logger.

    Safe to call multiple times — subsequent calls are no-ops so library
    consumers don't fight each other over handler registration.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    if os.environ.get("HALDIR_LOG_SILENT") == "1":
        logging.getLogger().addHandler(logging.NullHandler())
        _CONFIGURED = True
        return

    effective_level = (
        level
        or os.environ.get("HALDIR_LOG_LEVEL")
        or "INFO"
    ).upper()

    if json_output is None:
        json_output = os.environ.get("HALDIR_LOG_JSON", "1") != "0"

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if json_output else TextFormatter())

    root = logging.getLogger()
    root.setLevel(effective_level)
    # Replace any pre-existing handlers so we don't double-log under
    # werkzeug's or gunicorn's default setup.
    root.handlers = [handler]

    # Quiet werkzeug's built-in access log; we emit our own below.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str = "haldir") -> logging.Logger:
    """Return a configured logger. Calls `configure_logging()` lazily so
    callers don't have to remember to wire it up at boot."""
    configure_logging()
    return logging.getLogger(name)
