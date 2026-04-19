"""
Tests for haldir_metrics — the dependency-free Prometheus registry and
the `/metrics` HTTP endpoint.

Run: python -m pytest tests/test_metrics.py -v
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_metrics import Counter, Histogram, Registry


# ── Counter ─────────────────────────────────────────────────────────────

def test_counter_starts_empty() -> None:
    c = Counter("widgets_total", "Total widgets", label_names=("kind",))
    out = "\n".join(c.render())
    assert "# TYPE widgets_total counter" in out
    # No series emitted before first inc.
    assert "widgets_total{" not in out


def test_counter_increments_and_renders() -> None:
    c = Counter("widgets_total", "Total widgets", label_names=("kind",))
    c.inc(kind="red")
    c.inc(kind="red")
    c.inc(kind="blue", amount=3)
    out = "\n".join(c.render())
    assert 'widgets_total{kind="red"} 2.0' in out or 'widgets_total{kind="red"} 2' in out
    assert 'widgets_total{kind="blue"} 3' in out or 'widgets_total{kind="blue"} 3.0' in out


def test_counter_requires_declared_labels() -> None:
    c = Counter("widgets_total", "h", label_names=("kind",))
    try:
        c.inc()  # missing `kind`
    except ValueError as e:
        assert "kind" in str(e)
    else:
        raise AssertionError("expected ValueError for missing label")


def test_counter_escapes_label_values() -> None:
    """Backslashes, quotes, and newlines in label values must be escaped
    so the Prometheus parser can re-read our output."""
    c = Counter("reqs_total", "h", label_names=("path",))
    c.inc(path='/x"y\\z\n')
    out = "\n".join(c.render())
    # The escaped sequence should appear verbatim.
    assert '\\"' in out or '\\\\' in out


def test_counter_stable_ordering() -> None:
    """Rendering the same state twice must produce identical output —
    snapshot tests and diff tools depend on it."""
    c = Counter("reqs_total", "h", label_names=("path",))
    c.inc(path="/a")
    c.inc(path="/b")
    c.inc(path="/a")
    first = "\n".join(c.render())
    second = "\n".join(c.render())
    assert first == second


# ── Histogram ───────────────────────────────────────────────────────────

def test_histogram_emits_cumulative_buckets() -> None:
    h = Histogram(
        "latency_seconds", "h",
        label_names=("path",),
        buckets=(0.01, 0.1, 1.0),
    )
    h.observe(0.005, path="/x")  # below smallest bucket
    h.observe(0.05, path="/x")   # between 0.01 and 0.1
    h.observe(0.5, path="/x")    # between 0.1 and 1.0
    h.observe(5.0, path="/x")    # above largest bucket
    out = "\n".join(h.render())
    # Bucket counts are cumulative: le=0.01 → 1, le=0.1 → 2, le=1 → 3.
    # Label order is intentionally not asserted (Prometheus parsers don't
    # care) — we check for the `le=` value and bucket count separately.
    assert 'le="0.01"' in out and "_bucket" in out
    assert 'path="/x"' in out
    assert 'le="+Inf"' in out

    # Pull each bucket line and verify the counts.
    def _count_for(le_val: str) -> int:
        for line in out.splitlines():
            if "_bucket{" not in line:
                continue
            if f'le="{le_val}"' in line and 'path="/x"' in line:
                return int(line.rsplit(" ", 1)[-1])
        raise AssertionError(f"no bucket line for le={le_val!r}")

    assert _count_for("0.01") == 1
    assert _count_for("0.1") == 2
    assert _count_for("1") == 3
    assert _count_for("+Inf") == 4
    assert 'latency_seconds_count{path="/x"} 4' in out
    assert "latency_seconds_sum" in out


def test_histogram_multiple_series_independent() -> None:
    h = Histogram("lat_seconds", "h", label_names=("path",))
    h.observe(0.1, path="/a")
    h.observe(0.1, path="/b")
    h.observe(0.1, path="/b")
    out = "\n".join(h.render())
    assert 'lat_seconds_count{path="/a"} 1' in out
    assert 'lat_seconds_count{path="/b"} 2' in out


# ── Registry.render() ─────────────────────────────────────────────────

def test_registry_render_includes_all_metrics() -> None:
    reg = Registry()
    c = reg.counter("a_total", "first", ("lbl",))
    h = reg.histogram("b_seconds", "second", ("lbl",))
    c.inc(lbl="x")
    h.observe(0.05, lbl="x")
    out = reg.render()
    assert "# TYPE a_total counter" in out
    assert "# TYPE b_seconds histogram" in out
    assert out.endswith("\n")


# ── /metrics endpoint ───────────────────────────────────────────────────

def test_metrics_endpoint_refuses_without_token_set(haldir_client, monkeypatch) -> None:
    """If HALDIR_METRICS_TOKEN is unset, the endpoint must refuse
    entirely rather than leaking internal telemetry."""
    monkeypatch.delenv("HALDIR_METRICS_TOKEN", raising=False)
    r = haldir_client.get("/metrics")
    assert r.status_code == 503
    assert r.get_json()["code"] == "metrics_disabled"


def test_metrics_endpoint_requires_matching_token(haldir_client, monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_METRICS_TOKEN", "s3cr3t")
    r = haldir_client.get("/metrics")
    assert r.status_code == 401
    r = haldir_client.get("/metrics?token=wrong")
    assert r.status_code == 401


def test_metrics_endpoint_serves_prometheus_format(haldir_client, monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_METRICS_TOKEN", "s3cr3t")
    # Provoke at least one request so counters have data to render.
    haldir_client.get("/healthz")
    r = haldir_client.get("/metrics?token=s3cr3t")
    assert r.status_code == 200
    assert "text/plain" in r.content_type
    body = r.data.decode()
    assert "# TYPE haldir_http_requests_total counter" in body
    assert "# TYPE haldir_http_request_duration_seconds histogram" in body
    # The /healthz request should be reflected.
    assert 'path="/healthz"' in body


def test_metrics_endpoint_accepts_bearer_auth(haldir_client, monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_METRICS_TOKEN", "s3cr3t")
    r = haldir_client.get("/metrics", headers={"Authorization": "Bearer s3cr3t"})
    assert r.status_code == 200
