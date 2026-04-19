"""
Tests for haldir_logging — structured JSON logs with request-ID and
tenant-ID enrichment.

Run: python -m pytest tests/test_logging.py -v
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_logging import JsonFormatter, TextFormatter, get_logger, configure_logging


# ── Basic JSON envelope ─────────────────────────────────────────────────

def _emit(record_factory_kwargs=None, extras=None, formatter=None):
    """Build a LogRecord and run it through the formatter."""
    fmt = formatter or JsonFormatter()
    rec = logging.LogRecord(
        name="haldir.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    if extras:
        for k, v in extras.items():
            setattr(rec, k, v)
    return fmt.format(rec)


def test_json_formatter_emits_valid_json() -> None:
    out = _emit()
    parsed = json.loads(out)
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "haldir.test"
    assert parsed["msg"] == "hello world"


def test_json_formatter_includes_timestamp_in_iso8601_utc() -> None:
    out = _emit()
    parsed = json.loads(out)
    # Ends with "Z" (UTC) and contains milliseconds separator.
    assert parsed["ts"].endswith("Z")
    assert "T" in parsed["ts"]


def test_json_formatter_surfaces_extras() -> None:
    """Fields passed via log.info(..., extra={...}) appear at top level."""
    out = _emit(extras={"agent_id": "a-123", "status": 201})
    parsed = json.loads(out)
    assert parsed["agent_id"] == "a-123"
    assert parsed["status"] == 201


def test_json_formatter_serializes_exception_info() -> None:
    fmt = JsonFormatter()
    try:
        raise ValueError("boom")
    except ValueError:
        import sys as _sys
        rec = logging.LogRecord(
            name="haldir.test", level=logging.ERROR, pathname=__file__,
            lineno=1, msg="fail", args=(), exc_info=_sys.exc_info(),
        )
    out = fmt.format(rec)
    parsed = json.loads(out)
    assert "exc" in parsed
    assert "ValueError" in parsed["exc"]
    assert "boom" in parsed["exc"]


def test_json_formatter_skips_standard_attrs() -> None:
    """Internal LogRecord attributes (pathname, process, etc.) should
    not leak into the payload."""
    out = _emit()
    parsed = json.loads(out)
    for noisy in ("pathname", "args", "process", "threadName", "lineno"):
        assert noisy not in parsed


# ── Non-serializable values degrade gracefully ───────────────────────────

def test_json_formatter_handles_non_serializable() -> None:
    class Weird:
        def __repr__(self) -> str:
            return "<weird>"

    out = _emit(extras={"thing": Weird()})
    parsed = json.loads(out)
    assert parsed["thing"] == "<weird>"


# ── Flask context enrichment ────────────────────────────────────────────

def test_flask_context_enrichment_outside_request_is_a_no_op() -> None:
    """Calling the formatter outside a Flask request context must not crash."""
    out = _emit()
    parsed = json.loads(out)
    # No request_id / tenant_id outside a request.
    assert "request_id" not in parsed


def test_flask_context_enrichment_inside_request(haldir_client) -> None:
    """When a Flask request is in flight, the formatter picks up the
    request-ID off `g` and emits it at the top level."""
    import api

    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    api.log.addHandler(handler)
    # Ensure the extra handler actually receives records.
    prior_level = api.log.level
    api.log.setLevel(logging.INFO)
    try:
        haldir_client.get("/healthz", headers={"X-Request-ID": "rid-abc-123"})
    finally:
        api.log.removeHandler(handler)
        api.log.setLevel(prior_level)

    # Access log is suppressed for /healthz by default, so hit another
    # path to provoke a log line.
    buf.truncate(0)
    buf.seek(0)
    api.log.addHandler(handler)
    try:
        haldir_client.get("/nonexistent", headers={"X-Request-ID": "rid-xyz-999"})
    finally:
        api.log.removeHandler(handler)

    lines = [line for line in buf.getvalue().splitlines() if line.strip()]
    # At least one of the emitted lines should carry the request_id.
    matched = [line for line in lines if "rid-xyz-999" in line]
    assert matched, f"expected request_id in logs; got: {lines!r}"
    for line in matched:
        parsed = json.loads(line)
        assert parsed["request_id"] == "rid-xyz-999"


# ── Text formatter ──────────────────────────────────────────────────────

def test_text_formatter_is_human_readable() -> None:
    out = _emit(extras={"status": 200}, formatter=TextFormatter())
    assert "INFO" in out
    assert "haldir.test" in out
    assert "hello world" in out
    assert "status=200" in out


# ── configure_logging is idempotent ─────────────────────────────────────

def test_configure_logging_idempotent() -> None:
    """Multiple calls should not double-register handlers or fight each
    other's output."""
    configure_logging()
    before = len(logging.getLogger().handlers)
    configure_logging()
    configure_logging()
    after = len(logging.getLogger().handlers)
    assert before == after


def test_get_logger_returns_stdlib_logger() -> None:
    logger = get_logger("haldir.test.retrieval")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "haldir.test.retrieval"
