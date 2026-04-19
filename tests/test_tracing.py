"""
Tests for haldir_tracing — the OpenTelemetry shim.

Tracing is a non-invasive, opt-in feature. Default-off means:
  - `traced()` context manager is a no-op (no span emitted)
  - `traced_span()` decorator returns the function unchanged
  - Zero runtime overhead in the default install

Run: python -m pytest tests/test_tracing.py -v
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_tracing import is_enabled, traced, traced_span


# ── Default state: disabled ──────────────────────────────────────────────

def test_default_install_is_disabled() -> None:
    """Without HALDIR_TRACING_ENABLED set, tracing is off."""
    # The module is imported with the env var absent; is_enabled should be False.
    # This holds regardless of whether opentelemetry is installed locally.
    # (The env var is read at import time — setting it here won't flip it.)
    env = os.environ.get("HALDIR_TRACING_ENABLED", "").lower()
    if env in ("1", "true", "yes"):
        # Skip — user has enabled tracing locally; assertion doesn't apply
        return
    assert is_enabled() is False


# ── No-op context manager behaviour ──────────────────────────────────────

def test_traced_context_manager_is_inert_when_disabled() -> None:
    """When disabled, `traced()` should not raise and should yield None."""
    with traced("haldir.test.span") as span:
        assert span is None


def test_traced_context_manager_yields_even_with_attributes() -> None:
    with traced("haldir.test.with_attrs", foo="bar", count=42) as span:
        assert span is None


def test_traced_propagates_exceptions_when_disabled() -> None:
    """Exceptions inside the block must still propagate — tracing is
    observability, not swallowing."""
    import pytest
    with pytest.raises(ValueError, match="boom"):
        with traced("haldir.test.raises"):
            raise ValueError("boom")


# ── Decorator behaviour ──────────────────────────────────────────────────

def test_traced_span_decorator_preserves_return_value() -> None:
    @traced_span("haldir.test.decorated")
    def add(a: int, b: int) -> int:
        return a + b

    assert add(2, 3) == 5


def test_traced_span_decorator_preserves_exceptions() -> None:
    @traced_span("haldir.test.raises")
    def boom() -> None:
        raise RuntimeError("kaboom")

    import pytest
    with pytest.raises(RuntimeError, match="kaboom"):
        boom()


def test_traced_span_decorator_preserves_function_metadata() -> None:
    """functools.wraps preserves __name__, __doc__, etc."""
    @traced_span("haldir.test.named")
    def documented_fn() -> int:
        """Important docstring."""
        return 1

    # Either the decorator short-circuits to identity (when disabled) or it
    # wraps via functools.wraps. In both cases __name__/__doc__ should match.
    assert documented_fn.__name__ == "documented_fn"
    assert documented_fn.__doc__ == "Important docstring."


# ── When disabled, no performance overhead ────────────────────────────────

def test_traced_span_with_many_calls_does_not_explode() -> None:
    """Sanity check: 10k calls through a decorated function don't blow up."""
    @traced_span("haldir.test.hot_path")
    def cheap() -> int:
        return 1

    total = 0
    for _ in range(10_000):
        total += cheap()
    assert total == 10_000
