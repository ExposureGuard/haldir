"""
Haldir Tracing — OpenTelemetry instrumentation for Gate, Vault, Watch, Proxy.

Produces OTLP spans for every permission check, secret retrieval, audit
write, and policy enforcement decision. Enterprise customers (SOC 2,
HIPAA) need distributed-tracing support to correlate governance events
with their own agent traces.

## How it works

Instrumentation is **opt-in** and **non-invasive**:

  - If the `opentelemetry-api` package is installed AND
    `HALDIR_TRACING_ENABLED=1`, real spans are emitted via the global
    OpenTelemetry Tracer.
  - Otherwise, `traced_span(...)` returns a no-op context manager that
    compiles to nothing. Adding the decorator to a hot-path function
    costs a branch + dict lookup at import time, not per call.

This keeps Haldir's default-install footprint small (no OTel deps
required) while making observability a one-env-var flip for users who
want it.

## What's instrumented

Spans are emitted at the coarse governance boundaries — the decisions
a security auditor or SRE wants to see in a trace:

  - `haldir.gate.check_permission`    — scope check result
  - `haldir.gate.create_session`      — new session + its scopes
  - `haldir.gate.revoke_session`      — kill-switch invocation
  - `haldir.vault.get_secret`         — secret retrieval (name, NOT value)
  - `haldir.vault.store_secret`       — new secret stored
  - `haldir.watch.log_action`         — audit entry written
  - `haldir.proxy.call_tool`          — upstream tool call intercepted
  - `haldir.proxy.enforce_policies`   — policy evaluation result

## Usage

### Environment

    pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp
    export HALDIR_TRACING_ENABLED=1
    export OTEL_EXPORTER_OTLP_ENDPOINT=https://your-collector:4317
    export OTEL_SERVICE_NAME=haldir

### In code (already done in haldir_gate/vault/watch/proxy)

    from haldir_tracing import traced_span

    @traced_span("haldir.gate.check_permission")
    def check_permission(self, session_id: str, scope: str, tenant_id: str = "") -> bool:
        ...
"""

from __future__ import annotations

import functools
import os
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional, TypeVar


F = TypeVar("F", bound=Callable[..., Any])


# ── Detect OTel at import time ───────────────────────────────────────────

_ENABLED = os.environ.get("HALDIR_TRACING_ENABLED", "").lower() in ("1", "true", "yes")
_tracer: Any = None

if _ENABLED:
    try:
        from opentelemetry import trace as _ot_trace  # type: ignore[import-not-found]
        _tracer = _ot_trace.get_tracer("haldir", "0.3.0")
    except ImportError:
        # OTel requested but not installed — silently fall back to no-op
        _tracer = None
        _ENABLED = False


# ── Public API: traced_span context manager + decorator ──────────────────

@contextmanager
def traced(name: str, **attributes: Any) -> Iterator[Any]:
    """Context manager that emits an OTel span if tracing is enabled,
    or a no-op context if not.

    Usage:

        with traced("haldir.vault.get_secret", name="stripe_key", tenant_id="alice"):
            ...

    Attributes are attached to the span (if real) or discarded (if noop).
    Sensitive values (plaintext secrets, raw session IDs that have not
    been truncated) MUST NOT be passed as attributes.
    """
    if not _ENABLED or _tracer is None:
        yield None
        return

    with _tracer.start_as_current_span(name) as span:
        for k, v in attributes.items():
            try:
                span.set_attribute(k, v)
            except Exception:
                pass
        try:
            yield span
        except Exception as e:
            # Record the exception on the span so traces show the error
            try:
                span.record_exception(e)
                # StatusCode.ERROR = 2 in OTel's enum
                from opentelemetry.trace import Status, StatusCode  # type: ignore[import-not-found]
                span.set_status(Status(StatusCode.ERROR, str(e)))
            except Exception:
                pass
            raise


def traced_span(name: str) -> Callable[[F], F]:
    """Decorator form of `traced`. Use on methods you want a span around.

    No arguments from the call are added as attributes automatically —
    callers should use the `traced()` context manager inline when they
    need specific attribute capture.
    """
    def decorator(fn: F) -> F:
        if not _ENABLED or _tracer is None:
            return fn  # zero-cost passthrough when disabled

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with traced(name):
                return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def is_enabled() -> bool:
    """Whether tracing is actively emitting spans. Useful in tests."""
    return bool(_ENABLED and _tracer is not None)
