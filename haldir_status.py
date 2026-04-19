"""
Haldir status module — feeds the public /status page and /v1/status JSON.

Every SaaS of any credibility publishes a status page: a public URL
customers can hit to see whether the API is healthy right now and what
the recent track record looks like. This module produces the data that
page renders from:

  - Per-component health (API, database, Stripe billing, MCP proxy),
    each expressed as `ok | degraded | down` with a short message.
  - An overall verdict computed from the component worst-case.
  - Traffic-weighted success rate (% of recent HTTP requests that did
    not 5xx), drawn from haldir_http_requests_total.
  - p50/p95/p99 latency from the haldir_http_request_duration_seconds
    histogram — exposes the same signal your SRE dashboards use.

Design notes:

  - Pure-function reads against the metrics registry. No cron, no
    sampling thread; the status page calls these at request time so the
    data is always fresh and the module has no mutable state of its own.
  - Database check runs a cheap `SELECT 1` with a 1-second timeout so a
    wedged DB can't block the status page (the very thing people check
    when the DB is wedged).
  - Percentile computation is conservative: we return the upper edge of
    the bucket the p-th request falls into, which is the standard
    Prometheus histogram_quantile approach at histogram fidelity. For
    seed-stage traffic levels this is more than accurate enough; once
    we're pushing enough RPS to care, we'll swap in a proper TDigest.

The module deliberately knows nothing about Flask — it takes a DB path
and the metrics registry as arguments — so it can be exercised by unit
tests without spinning up an HTTP server.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass, asdict
from typing import Any

from haldir_metrics import Counter, Histogram, Registry


# Component labels. Fixed ordering so the public page is stable.
_COMPONENT_ORDER = ("api", "database", "billing", "proxy")

# Overall state precedence: "down" > "degraded" > "ok". A single down
# component turns the banner red; a degraded dep turns it yellow.
_STATE_RANK = {"ok": 0, "degraded": 1, "down": 2}


@dataclass
class ComponentStatus:
    """Health of one piece of the system, plus a human-readable reason."""
    name: str
    state: str          # "ok" | "degraded" | "down"
    message: str
    checked_at: float   # unix seconds

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Individual component checks ────────────────────────────────────────

def check_api() -> ComponentStatus:
    """The API is reachable by definition — if it weren't, nobody would
    be rendering this check. Always ok, but we still emit the row so the
    public status page shows the full component list."""
    return ComponentStatus(
        name="api",
        state="ok",
        message="Serving requests",
        checked_at=time.time(),
    )


def check_database(db_path: str, timeout_s: float = 1.0) -> ComponentStatus:
    """Ping the database with a trivial `SELECT 1`. Treat slow responses
    (> half the timeout) as `degraded` — a sign the DB is alive but
    struggling, which is something customers should see rather than
    learn about from 500s."""
    start = time.time()
    try:
        conn = sqlite3.connect(db_path, timeout=timeout_s)
        try:
            cur = conn.execute("SELECT 1")
            cur.fetchone()
        finally:
            conn.close()
    except Exception as e:
        return ComponentStatus(
            name="database",
            state="down",
            message=f"Query failed: {type(e).__name__}",
            checked_at=time.time(),
        )
    elapsed = time.time() - start
    if elapsed > timeout_s / 2:
        return ComponentStatus(
            name="database",
            state="degraded",
            message=f"Slow response ({elapsed * 1000:.0f} ms)",
            checked_at=time.time(),
        )
    return ComponentStatus(
        name="database",
        state="ok",
        message=f"Responsive ({elapsed * 1000:.0f} ms)",
        checked_at=time.time(),
    )


def check_billing() -> ComponentStatus:
    """Stripe is a configuration-gated dependency. If STRIPE_SECRET_KEY
    isn't set we report the feature as `degraded` rather than `down`
    because a self-hosted Haldir may deliberately run without Stripe;
    we don't want that to trip the overall banner red."""
    if os.environ.get("STRIPE_SECRET_KEY"):
        return ComponentStatus(
            name="billing",
            state="ok",
            message="Stripe configured",
            checked_at=time.time(),
        )
    return ComponentStatus(
        name="billing",
        state="degraded",
        message="Stripe unconfigured (self-hosted deploys may intentionally skip)",
        checked_at=time.time(),
    )


def check_proxy(db_path: str) -> ComponentStatus:
    """The MCP proxy is optional — tenants configure upstreams via
    POST /v1/proxy/upstreams. Report `ok` once any upstream exists;
    until then it's `degraded` (feature available but unused)."""
    try:
        conn = sqlite3.connect(db_path, timeout=1.0)
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM proxy_upstreams"
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.OperationalError:
        # Table absent on a fresh bootstrap — proxy unused.
        return ComponentStatus(
            name="proxy",
            state="degraded",
            message="No upstream MCP servers registered",
            checked_at=time.time(),
        )
    except Exception as e:
        return ComponentStatus(
            name="proxy",
            state="down",
            message=f"Lookup failed: {type(e).__name__}",
            checked_at=time.time(),
        )
    count = int(row[0]) if row else 0
    if count == 0:
        return ComponentStatus(
            name="proxy",
            state="degraded",
            message="No upstream MCP servers registered",
            checked_at=time.time(),
        )
    return ComponentStatus(
        name="proxy",
        state="ok",
        message=f"{count} upstream server(s) registered",
        checked_at=time.time(),
    )


def all_components(db_path: str) -> list[ComponentStatus]:
    """Run every check in the stable declared order. Used by both the
    JSON payload and the HTML page."""
    lookup = {
        "api": check_api,
        "database": lambda: check_database(db_path),
        "billing": check_billing,
        "proxy": lambda: check_proxy(db_path),
    }
    return [lookup[name]() for name in _COMPONENT_ORDER]


def overall_state(components: list[ComponentStatus]) -> str:
    """Worst-case roll-up: one `down` component turns the whole page
    red; any `degraded` turns it yellow; otherwise green."""
    worst = 0
    for c in components:
        worst = max(worst, _STATE_RANK.get(c.state, 0))
    for state, rank in _STATE_RANK.items():
        if rank == worst:
            return state
    return "ok"


# ── Metric-derived SLIs ────────────────────────────────────────────────

def _find(registry: Registry, name: str) -> Counter | Histogram | None:
    """Return the metric with the given name, or None if it isn't
    registered (lets tests run against a bare registry)."""
    for m in registry._metrics:  # noqa: SLF001 — intentional internal read
        if m.name == name:
            return m
    return None


def success_rate(registry: Registry) -> dict[str, Any]:
    """Fraction of recorded HTTP requests whose status is not 5xx.

    Returns {total, errors, ratio} rather than a bare float so the
    status page can render "99.97% (3/10,241)" rather than a context-free
    percentage. Ratio is 1.0 (100%) when no traffic has been recorded —
    a fresh deploy isn't "failing", it just hasn't been tested yet."""
    counter = _find(registry, "haldir_http_requests_total")
    if not isinstance(counter, Counter):
        return {"total": 0, "errors": 0, "ratio": 1.0}
    total = 0.0
    errors = 0.0
    for labels, value in counter.snapshot().items():
        total += value
        status = dict(labels).get("status", "")
        if status.startswith("5"):
            errors += value
    ratio = 1.0 if total == 0 else (total - errors) / total
    return {"total": int(total), "errors": int(errors), "ratio": ratio}


def latency_percentile(registry: Registry, percentile: float) -> float | None:
    """Estimate the `percentile`-th request-duration across all labels,
    in seconds. Returns None when no observations have been recorded.

    Uses the standard Prometheus histogram_quantile algorithm at
    bucket fidelity: find the bucket where cumulative count crosses
    the requested quantile and return its upper bound. This is
    conservative (rounds up to the next bucket edge) but stable and
    matches what Grafana would show off the same histogram."""
    if not 0.0 < percentile < 1.0:
        raise ValueError("percentile must be in (0, 1)")

    hist = _find(registry, "haldir_http_request_duration_seconds")
    if not isinstance(hist, Histogram):
        return None

    # Aggregate across every label series — the status page shows one
    # top-line latency, not a breakdown per route.
    total_count = 0
    bucket_sums = [0] * len(hist.buckets)
    for _, series in hist.snapshot().items():
        total_count += series.count
        for i, c in enumerate(series.buckets):
            bucket_sums[i] += c
    if total_count == 0:
        return None
    target = percentile * total_count
    for i, cumulative in enumerate(bucket_sums):
        if cumulative >= target:
            return hist.buckets[i]
    # Target falls beyond the largest bucket — fall back to +Inf proxy.
    return hist.buckets[-1]


# ── Top-level snapshot ─────────────────────────────────────────────────

def build_status(db_path: str, registry: Registry) -> dict[str, Any]:
    """Compose the full status payload: components, overall verdict,
    traffic-weighted success rate, and latency percentiles."""
    components = all_components(db_path)
    return {
        "status": overall_state(components),
        "checked_at": time.time(),
        "components": [c.to_dict() for c in components],
        "metrics": {
            "success_rate": success_rate(registry),
            "latency_seconds": {
                "p50": latency_percentile(registry, 0.50),
                "p95": latency_percentile(registry, 0.95),
                "p99": latency_percentile(registry, 0.99),
            },
        },
    }
