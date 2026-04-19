"""
Tests for haldir_status — the module that feeds the public /status page
and /v1/status JSON endpoint.

Run: python -m pytest tests/test_status.py -v
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_metrics  # noqa: E402
from haldir_metrics import Registry  # noqa: E402
from haldir_status import (  # noqa: E402
    ComponentStatus,
    all_components,
    build_status,
    check_api,
    check_billing,
    check_database,
    check_proxy,
    latency_percentile,
    overall_state,
    success_rate,
)


# ── Component checks ───────────────────────────────────────────────────

def test_check_api_always_ok() -> None:
    s = check_api()
    assert s.state == "ok"
    assert s.name == "api"


def test_check_database_ok_on_reachable_sqlite(tmp_path) -> None:
    db = tmp_path / "hs.db"
    # Create an empty sqlite file so SELECT 1 succeeds.
    sqlite3.connect(str(db)).close()
    s = check_database(str(db))
    assert s.state == "ok"
    assert "ms" in s.message


def test_check_database_down_on_unreachable_path(tmp_path) -> None:
    # sqlite3.connect() creates missing files, so use a path we can't
    # create in (a non-existent directory).
    bogus = tmp_path / "does" / "not" / "exist" / "hs.db"
    s = check_database(str(bogus))
    assert s.state == "down"
    assert "failed" in s.message.lower()


def test_check_billing_degraded_without_stripe_key(monkeypatch) -> None:
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    s = check_billing()
    assert s.state == "degraded"


def test_check_billing_ok_with_stripe_key(monkeypatch) -> None:
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_dummy")
    s = check_billing()
    assert s.state == "ok"


def test_check_proxy_degraded_when_no_upstream_table(tmp_path) -> None:
    db = tmp_path / "empty.db"
    sqlite3.connect(str(db)).close()  # no proxy_upstreams table
    s = check_proxy(str(db))
    assert s.state == "degraded"


def test_check_proxy_ok_when_upstreams_present(tmp_path) -> None:
    db = tmp_path / "p.db"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE proxy_upstreams (id INTEGER PRIMARY KEY, url TEXT)"
    )
    conn.execute("INSERT INTO proxy_upstreams (url) VALUES ('https://a')")
    conn.commit()
    conn.close()
    s = check_proxy(str(db))
    assert s.state == "ok"
    assert "1 upstream" in s.message


# ── Overall roll-up ────────────────────────────────────────────────────

def _c(name: str, state: str) -> ComponentStatus:
    return ComponentStatus(name=name, state=state, message="", checked_at=0.0)


def test_overall_all_ok_is_ok() -> None:
    assert overall_state([_c("a", "ok"), _c("b", "ok")]) == "ok"


def test_overall_any_degraded_is_degraded() -> None:
    assert overall_state([_c("a", "ok"), _c("b", "degraded")]) == "degraded"


def test_overall_any_down_trumps_degraded() -> None:
    assert (
        overall_state([_c("a", "down"), _c("b", "degraded")]) == "down"
    )


# ── Metric-derived SLIs ────────────────────────────────────────────────

def test_success_rate_is_one_when_no_traffic() -> None:
    reg = Registry()
    sr = success_rate(reg)
    assert sr["total"] == 0
    assert sr["ratio"] == 1.0


def test_success_rate_counts_5xx_as_errors() -> None:
    reg = Registry()
    counter = reg.counter(
        "haldir_http_requests_total",
        "test",
        label_names=("method", "path", "status"),
    )
    for _ in range(9):
        counter.inc(method="GET", path="/x", status="200")
    counter.inc(method="GET", path="/x", status="500")
    sr = success_rate(reg)
    assert sr["total"] == 10
    assert sr["errors"] == 1
    assert sr["ratio"] == pytest.approx(0.9, rel=1e-3)


def test_success_rate_ignores_non_5xx_errors() -> None:
    """4xx is the client's fault, not the server's — shouldn't drag
    down the 'is the service healthy' metric."""
    reg = Registry()
    counter = reg.counter(
        "haldir_http_requests_total",
        "test",
        label_names=("method", "path", "status"),
    )
    counter.inc(method="GET", path="/x", status="200")
    counter.inc(method="GET", path="/x", status="404")
    counter.inc(method="GET", path="/x", status="401")
    sr = success_rate(reg)
    assert sr["errors"] == 0
    assert sr["ratio"] == 1.0


def test_latency_percentile_returns_none_on_empty() -> None:
    reg = Registry()
    assert latency_percentile(reg, 0.95) is None


def test_latency_percentile_p95_lands_in_right_bucket() -> None:
    reg = Registry()
    hist = reg.histogram(
        "haldir_http_request_duration_seconds",
        "test",
        label_names=("method", "path"),
    )
    # 100 observations: 95 fast (5 ms), 5 slow (500 ms). p95 should
    # return a bucket upper bound at or above the 95th observation.
    for _ in range(95):
        hist.observe(0.005, method="GET", path="/x")
    for _ in range(5):
        hist.observe(0.500, method="GET", path="/x")
    p50 = latency_percentile(reg, 0.50)
    p95 = latency_percentile(reg, 0.95)
    p99 = latency_percentile(reg, 0.99)
    assert p50 is not None and p50 <= 0.010
    assert p95 is not None and p95 <= 0.010
    assert p99 is not None and p99 >= 0.250


def test_latency_percentile_rejects_out_of_range() -> None:
    reg = Registry()
    with pytest.raises(ValueError):
        latency_percentile(reg, 0.0)
    with pytest.raises(ValueError):
        latency_percentile(reg, 1.0)


# ── Top-level snapshot ────────────────────────────────────────────────

def test_build_status_shape(tmp_path, monkeypatch) -> None:
    db = tmp_path / "build.db"
    sqlite3.connect(str(db)).close()
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    reg = Registry()

    snap = build_status(str(db), reg)
    assert snap["status"] in ("ok", "degraded", "down")
    assert {c["name"] for c in snap["components"]} == {
        "api", "database", "billing", "proxy",
    }
    m = snap["metrics"]
    assert set(m["latency_seconds"].keys()) == {"p50", "p95", "p99"}
    assert m["success_rate"]["ratio"] == 1.0


def test_all_components_stable_order(tmp_path) -> None:
    db = tmp_path / "o.db"
    sqlite3.connect(str(db)).close()
    comps = all_components(str(db))
    assert [c.name for c in comps] == ["api", "database", "billing", "proxy"]


# ── End-to-end via the Flask endpoints ─────────────────────────────────

def test_status_json_endpoint_serves_payload(haldir_client) -> None:
    r = haldir_client.get("/v1/status")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] in ("ok", "degraded", "down")
    assert "components" in data
    assert "metrics" in data


def test_status_html_page_renders(haldir_client) -> None:
    r = haldir_client.get("/status")
    assert r.status_code == 200
    assert "text/html" in r.content_type
    body = r.data.decode()
    # Every component should surface in the page.
    for name in ("api", "database", "billing", "proxy"):
        assert name in body
    # The banner text is one of the three canonical phrasings.
    assert any(
        phrase in body for phrase in (
            "All systems operational",
            "Partial degradation",
            "Service disruption",
        )
    )


def test_status_page_excluded_from_openapi_spec() -> None:
    """The HTML status page isn't part of the JSON API surface; the
    OpenAPI generator should skip it. The machine-readable /v1/status
    *should* appear."""
    import api
    from haldir_openapi import generate_openapi
    spec = generate_openapi(api.app)
    assert "/status" not in spec["paths"]
    assert "/v1/status" in spec["paths"]
