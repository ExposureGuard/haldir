"""
Haldir concurrent HTTP throughput benchmark.

Launches Haldir under gunicorn on a local port, bootstraps an API key,
then hits representative endpoints with N concurrent workers for a fixed
duration. Emits a Markdown table of RPS, success rate, p50 / p95 / p99
latency — the numbers README.md quotes and technical buyers actually
want to see before taking a dependency.

Why this benchmark exists alongside bench_primitives.py:

  - bench_primitives.py measures the cost of a single call (crypto,
    hash chain, one REST round-trip) in isolation. That answers "how
    heavy is the primitive?"
  - bench_http.py measures throughput under concurrency against the
    real production server (gunicorn, not Flask's dev loop) with real
    middleware in the path (auth + metrics + structured logging). That
    answers "how many agents can one box govern before latency moves?"

Usage:
    python bench/bench_http.py               # defaults: 4 workers, 32
                                             # clients, 10 s per endpoint
    python bench/bench_http.py --duration 30 --concurrency 64

Notes:
  - SQLite backs a temp DB so runs never touch real data.
  - First few hundred ms are warmup (JIT caches, DB page cache); the
    harness drops the first 10% of samples per scenario before
    computing percentiles.
  - Latency numbers include localhost TCP + HTTP round-trip, so they
    represent what a same-datacenter client would see.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from typing import Callable


# ── Server lifecycle ──────────────────────────────────────────────────

def _free_port() -> int:
    """Grab an unused localhost port. Small race window between close()
    and gunicorn bind(), but fine for a single-process benchmark."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_ready(port: int, timeout_s: float = 15.0) -> None:
    """Poll /healthz until the server answers or timeout."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1.0)
            conn.request("GET", "/healthz")
            if conn.getresponse().status == 200:
                return
        except Exception:
            time.sleep(0.2)
        finally:
            try:
                conn.close()  # type: ignore[possibly-undefined]
            except Exception:
                pass
    raise RuntimeError(f"server never came up on :{port}")


def _spawn_server(port: int, workers: int, db_path: str) -> subprocess.Popen:
    env = dict(os.environ)
    env["HALDIR_DB_PATH"] = db_path
    env["HALDIR_LOG_LEVEL"] = "WARNING"  # quiet the scrape noise
    env["HALDIR_LOG_SILENT"] = "1"
    env.pop("STRIPE_SECRET_KEY", None)  # never hit live Stripe during bench
    cmd = [
        sys.executable, "-m", "gunicorn",
        "api:app",
        "-w", str(workers),
        "-b", f"127.0.0.1:{port}",
        "--log-level", "warning",
        "--access-logfile", "-",
        "--access-logformat", "",  # suppress access log noise
        "--timeout", "30",
    ]
    return subprocess.Popen(
        cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )


# ── Client loop ───────────────────────────────────────────────────────

def _bootstrap_key(port: int) -> str:
    """Mint a bootstrap API key the authed scenarios can use."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = json.dumps({"name": "bench", "tier": "pro"})
    conn.request("POST", "/v1/keys", body=body,
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    payload = resp.read()
    conn.close()
    if resp.status != 201:
        raise RuntimeError(f"bootstrap failed: {resp.status} {payload!r}")
    return json.loads(payload)["key"]


def _create_session(port: int, api_key: str) -> str:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = json.dumps({"agent_id": "bench", "scopes": ["read", "execute"]})
    conn.request("POST", "/v1/sessions", body=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    })
    resp = conn.getresponse()
    payload = resp.read()
    conn.close()
    if resp.status != 201:
        raise RuntimeError(f"session bootstrap failed: {resp.status} {payload!r}")
    return json.loads(payload)["session_id"]


def _worker(
    port: int,
    build_request: Callable[[], tuple[str, str, bytes | None, dict[str, str]]],
    duration_s: float,
    samples: list[float],
    successes: list[int],
    failures: list[int],
    stop: threading.Event,
) -> None:
    """One worker thread: keep a persistent TCP connection to the
    server and loop for `duration_s` seconds, appending every latency
    to a shared list."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    end = time.time() + duration_s
    local_samples: list[float] = []
    ok = 0
    fail = 0
    while time.time() < end and not stop.is_set():
        method, path, body, headers = build_request()
        t0 = time.perf_counter()
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp.read()
            elapsed = time.perf_counter() - t0
            local_samples.append(elapsed)
            if 200 <= resp.status < 500:
                ok += 1
            else:
                fail += 1
        except Exception:
            fail += 1
            # Reset the connection after any TCP-level hiccup.
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.close()
    samples.extend(local_samples)
    successes.append(ok)
    failures.append(fail)


def _run_scenario(
    name: str,
    port: int,
    build_request: Callable[[], tuple[str, str, bytes | None, dict[str, str]]],
    duration_s: float,
    concurrency: int,
) -> dict[str, object]:
    samples: list[float] = []
    successes: list[int] = []
    failures: list[int] = []
    stop = threading.Event()

    threads = [
        threading.Thread(
            target=_worker,
            args=(port, build_request, duration_s, samples,
                  successes, failures, stop),
            daemon=True,
        )
        for _ in range(concurrency)
    ]
    start = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=duration_s + 30)
    wall = time.perf_counter() - start

    # Drop the first 10% as warmup (cold JIT caches, DB page cache,
    # gunicorn worker priming). Leaves enough samples that the tail
    # percentiles remain meaningful.
    samples_sorted = sorted(samples)
    warmup = max(1, len(samples_sorted) // 10)
    hot = samples_sorted[warmup:]

    total_ok = sum(successes)
    total_fail = sum(failures)
    total = total_ok + total_fail

    return {
        "name":     name,
        "requests": total,
        "errors":   total_fail,
        "rps":      total / wall if wall > 0 else 0.0,
        "p50_ms":   _pct(hot, 0.50) * 1000 if hot else 0,
        "p95_ms":   _pct(hot, 0.95) * 1000 if hot else 0,
        "p99_ms":   _pct(hot, 0.99) * 1000 if hot else 0,
        "mean_ms":  (sum(hot) / len(hot)) * 1000 if hot else 0,
    }


def _pct(sorted_samples: list[float], p: float) -> float:
    """Linear-interpolated percentile. Standard NIST method C=1."""
    if not sorted_samples:
        return 0.0
    k = (len(sorted_samples) - 1) * p
    f = int(k)
    c = min(f + 1, len(sorted_samples) - 1)
    if f == c:
        return sorted_samples[f]
    return sorted_samples[f] * (c - k) + sorted_samples[c] * (k - f)


# ── Scenario catalog ──────────────────────────────────────────────────

def _scenarios(api_key: str, session_id: str) -> list[tuple[str, Callable]]:
    auth = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    def healthz() -> tuple[str, str, bytes | None, dict[str, str]]:
        return "GET", "/healthz", None, {}

    def status_json() -> tuple[str, str, bytes | None, dict[str, str]]:
        return "GET", "/v1/status", None, {}

    def session_get() -> tuple[str, str, bytes | None, dict[str, str]]:
        return "GET", f"/v1/sessions/{session_id}", None, auth

    def session_create() -> tuple[str, str, bytes | None, dict[str, str]]:
        body = json.dumps({
            "agent_id": f"bench-{uuid.uuid4().hex[:8]}",
            "scopes": ["read", "execute"],
        }).encode()
        return "POST", "/v1/sessions", body, auth

    def audit_write() -> tuple[str, str, bytes | None, dict[str, str]]:
        body = json.dumps({
            "session_id": session_id,
            "tool": "bench",
            "action": "ping",
            "cost_usd": 0.0,
        }).encode()
        return "POST", "/v1/audit", body, auth

    return [
        ("GET  /healthz          ",       healthz),
        ("GET  /v1/status        ",       status_json),
        ("GET  /v1/sessions/:id  ",       session_get),
        ("POST /v1/sessions      ",       session_create),
        ("POST /v1/audit         ",       audit_write),
    ]


# ── Entrypoint ────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--workers", type=int, default=4,
                   help="gunicorn worker processes")
    p.add_argument("--concurrency", type=int, default=32,
                   help="concurrent client threads per scenario")
    p.add_argument("--duration", type=float, default=10.0,
                   help="seconds per scenario")
    p.add_argument("--port", type=int, default=0,
                   help="server port (0 = auto-pick)")
    p.add_argument("--markdown", action="store_true",
                   help="emit Markdown table only (no header noise)")
    args = p.parse_args()

    port = args.port or _free_port()
    db_file = tempfile.NamedTemporaryFile(prefix="haldir_bench_", suffix=".db",
                                          delete=False)
    db_file.close()
    proc = _spawn_server(port, args.workers, db_file.name)

    try:
        _wait_ready(port)
        api_key = _bootstrap_key(port)
        session_id = _create_session(port, api_key)

        results = []
        for name, builder in _scenarios(api_key, session_id):
            r = _run_scenario(name, port, builder, args.duration,
                              args.concurrency)
            results.append(r)

        if not args.markdown:
            print(f"\n=== Haldir HTTP throughput "
                  f"(gunicorn={args.workers}w, "
                  f"clients={args.concurrency}, "
                  f"duration={args.duration:.0f}s) ===\n")
        print("| Endpoint | Requests | RPS | p50 | p95 | p99 | Errors |")
        print("|---|---:|---:|---:|---:|---:|---:|")
        for r in results:
            print(
                f"| `{r['name'].strip()}` "
                f"| {r['requests']:,} "
                f"| {r['rps']:.0f} "
                f"| {r['p50_ms']:.1f} ms "
                f"| {r['p95_ms']:.1f} ms "
                f"| {r['p99_ms']:.1f} ms "
                f"| {r['errors']} |"
            )
        return 0
    finally:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        try:
            os.unlink(db_file.name)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
