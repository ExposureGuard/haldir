"""
Haldir in-process Prometheus metrics.

A tiny, dependency-free metrics registry that speaks the Prometheus text
exposition format. Good enough for single-node deployments; swap in
`prometheus_client` if Haldir ever fans out to a multi-process server.

Why in-process, no external dep?
  - Zero extra install footprint in the default `pip install haldir`.
  - Haldir runs as a single gunicorn/uwsgi process today. Multi-worker
    aggregation is a "when we have that problem" problem.
  - Prometheus text format is forward-compatible: once you swap to the
    real client, every scrape target keeps working unchanged.

Metrics exposed by default (defined in api.py):

  haldir_http_requests_total{method,path,status}
    Counter of every HTTP request the API handled, broken down by the
    usual RED triplet.

  haldir_http_request_duration_seconds{method,path}
    Histogram (buckets in seconds) — p50/p95/p99 latency per route.

  haldir_rate_limit_exceeded_total{tier}
    Counter of 429s, tagged by the tier whose limit was hit.

  haldir_idempotency_hits_total{endpoint}
    Counter of replay hits served from the idempotency cache.

  haldir_idempotency_mismatches_total{endpoint}
    Counter of Idempotency-Key reuses with a different body.

Callers touch this module exclusively through `registry` — the single
global instance the API registers metrics on at boot.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Iterable


# Prometheus-recommended default bucket set (seconds). Wide enough to
# cover a 5 ms cached lookup and a 5 s upstream MCP call. Adjust only
# with strong reason — dashboards hardcode these boundaries.
DEFAULT_BUCKETS: tuple[float, ...] = (
    0.005, 0.010, 0.025, 0.050, 0.100,
    0.250, 0.500, 1.0, 2.5, 5.0, 10.0,
)


def _fmt_labels(labels: tuple[tuple[str, str], ...]) -> str:
    """Render `{k="v",k2="v2"}` with alphabetical keys for stable output.
    Escapes backslashes and quotes per Prometheus exposition spec."""
    if not labels:
        return ""
    parts = []
    for k, v in labels:
        v_esc = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        parts.append(f'{k}="{v_esc}"')
    return "{" + ",".join(parts) + "}"


class Counter:
    """Monotonically increasing float counter (one series per label set)."""

    def __init__(self, name: str, help_text: str, label_names: tuple[str, ...] = ()) -> None:
        self.name = name
        self.help_text = help_text
        self.label_names = label_names
        self._values: dict[tuple[tuple[str, str], ...], float] = {}
        self._lock = threading.Lock()

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def _key(self, labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
        if self.label_names:
            missing = set(self.label_names) - labels.keys()
            if missing:
                raise ValueError(
                    f"{self.name}: missing labels {sorted(missing)}; got {sorted(labels)}"
                )
        # Sort for stable output & lookup; coerce to str so ints render.
        return tuple(sorted((k, str(v)) for k, v in labels.items()))

    def render(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.help_text}"
        yield f"# TYPE {self.name} counter"
        with self._lock:
            snapshot = dict(self._values)
        # Stable ordering for snapshot tests.
        for lbls, val in sorted(snapshot.items()):
            yield f"{self.name}{_fmt_labels(lbls)} {val}"


@dataclass
class _HistogramSeries:
    count: int = 0
    sum: float = 0.0
    buckets: list[int] = field(default_factory=list)


class Histogram:
    """Cumulative histogram with count + sum + per-bucket counters."""

    def __init__(
        self,
        name: str,
        help_text: str,
        label_names: tuple[str, ...] = (),
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
    ) -> None:
        self.name = name
        self.help_text = help_text
        self.label_names = label_names
        self.buckets = buckets
        self._series: dict[tuple[tuple[str, str], ...], _HistogramSeries] = {}
        self._lock = threading.Lock()

    def observe(self, value: float, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            s = self._series.get(key)
            if s is None:
                s = _HistogramSeries(buckets=[0] * len(self.buckets))
                self._series[key] = s
            s.count += 1
            s.sum += value
            for i, upper in enumerate(self.buckets):
                if value <= upper:
                    s.buckets[i] += 1

    def _key(self, labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
        if self.label_names:
            missing = set(self.label_names) - labels.keys()
            if missing:
                raise ValueError(
                    f"{self.name}: missing labels {sorted(missing)}; got {sorted(labels)}"
                )
        return tuple(sorted((k, str(v)) for k, v in labels.items()))

    def render(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.help_text}"
        yield f"# TYPE {self.name} histogram"
        with self._lock:
            snapshot = {
                k: _HistogramSeries(
                    count=v.count, sum=v.sum, buckets=list(v.buckets),
                )
                for k, v in self._series.items()
            }
        for lbls, s in sorted(snapshot.items()):
            # observe() already stores cumulative counts (every bucket with
            # upper >= value is incremented), so we emit directly.
            for i, upper in enumerate(self.buckets):
                le_label = lbls + (("le", _prom_float(upper)),)
                yield f"{self.name}_bucket{_fmt_labels(le_label)} {s.buckets[i]}"
            le_inf = lbls + (("le", "+Inf"),)
            yield f"{self.name}_bucket{_fmt_labels(le_inf)} {s.count}"
            yield f"{self.name}_sum{_fmt_labels(lbls)} {s.sum}"
            yield f"{self.name}_count{_fmt_labels(lbls)} {s.count}"


def _prom_float(x: float) -> str:
    """Render bucket upper bound as Prometheus likes it (0.05 stays 0.05,
    1.0 stays 1)."""
    if x == int(x):
        return str(int(x))
    return repr(x)


class Registry:
    """Bag of metrics with a `render()` entry point for the HTTP handler."""

    def __init__(self) -> None:
        self._metrics: list[Counter | Histogram] = []
        self._lock = threading.Lock()

    def register(self, metric: Counter | Histogram) -> None:
        with self._lock:
            self._metrics.append(metric)

    def counter(self, name: str, help_text: str, label_names: tuple[str, ...] = ()) -> Counter:
        c = Counter(name, help_text, label_names)
        self.register(c)
        return c

    def histogram(
        self,
        name: str,
        help_text: str,
        label_names: tuple[str, ...] = (),
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
    ) -> Histogram:
        h = Histogram(name, help_text, label_names, buckets)
        self.register(h)
        return h

    def render(self) -> str:
        """Produce the full scrape payload as Prometheus text format."""
        lines: list[str] = []
        with self._lock:
            metrics = list(self._metrics)
        for m in metrics:
            lines.extend(m.render())
            lines.append("")  # blank line between metric families
        # Trailing newline matches canonical Prometheus output.
        return "\n".join(lines).rstrip() + "\n"


# Module-level registry used by the API. Tests may call `reset()`.
registry = Registry()


def reset() -> None:
    """Reinitialize the global registry (test helper only)."""
    global registry
    registry = Registry()
