"""
Benchmark Haldir's core primitives against the live hosted API.

Measures end-to-end wall-clock latency (p50 / p95 / p99) for every
primitive an agent hits on a typical tool call. Includes:

  - Gate: create_session, check_permission, get_session
  - Vault: store_secret, get_secret (in-memory crypto path)
  - Watch: log_action (local hash compute + DB write)
  - Full governed-tool lifecycle (check → log in one path)

Usage:
    export HALDIR_API_KEY=hld_...
    python bench/bench_primitives.py
    # or for a one-off local measurement of only the crypto primitives:
    python bench/bench_primitives.py --local
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_vault import Vault
from haldir_watch.watch import AuditEntry


def _stats(samples: list[float]) -> dict:
    samples_ms = sorted(s * 1000 for s in samples)
    n = len(samples_ms)
    return {
        "n": n,
        "p50_ms": samples_ms[n // 2],
        "p95_ms": samples_ms[min(int(n * 0.95), n - 1)],
        "p99_ms": samples_ms[min(int(n * 0.99), n - 1)],
        "mean_ms": statistics.mean(samples_ms),
    }


def _print(name: str, s: dict) -> None:
    print(
        f"  {name:34} n={s['n']:4}  "
        f"p50 {s['p50_ms']:7.2f} ms  "
        f"p95 {s['p95_ms']:7.2f} ms  "
        f"p99 {s['p99_ms']:7.2f} ms  "
        f"mean {s['mean_ms']:7.2f} ms"
    )


# ── Local crypto + hash benchmarks (no network) ─────────────────────────

def bench_local(runs: int = 1000) -> None:
    print(f"\n=== Local primitives — AES-256-GCM Vault + SHA-256 Watch chain ({runs} iters) ===")

    key = Vault.generate_key()
    vault = Vault(encryption_key=key)

    # ── Vault encrypt (includes AAD binding overhead) ────────────────────
    samples = []
    for i in range(runs):
        t0 = time.perf_counter()
        vault.store_secret(name=f"k{i}", value="sk_live_supersecret_value_abc", tenant_id="t")
        samples.append(time.perf_counter() - t0)
    _print("Vault.store_secret (AES-256-GCM)", _stats(samples))

    # ── Vault decrypt ────────────────────────────────────────────────────
    samples = []
    for i in range(runs):
        t0 = time.perf_counter()
        vault.get_secret(name=f"k{i}", tenant_id="t")
        samples.append(time.perf_counter() - t0)
    _print("Vault.get_secret (AES-256-GCM)", _stats(samples))

    # ── AuditEntry.compute_hash (SHA-256 on canonical payload) ───────────
    samples = []
    for i in range(runs):
        entry = AuditEntry(
            entry_id=f"aud_{i}",
            session_id="ses_1",
            agent_id="agent-1",
            action="execute",
            tool="stripe",
            details={"amount": 10},
            cost_usd=1.50,
            timestamp=time.time(),
            flagged=False,
            tenant_id="t",
            prev_hash="a" * 64,
        )
        t0 = time.perf_counter()
        entry.compute_hash()
        samples.append(time.perf_counter() - t0)
    _print("AuditEntry.compute_hash (SHA-256)", _stats(samples))


# ── End-to-end benchmarks against hosted haldir.xyz ──────────────────────

def bench_remote(api_key: str, base_url: str = "https://haldir.xyz",
                 warmup: int = 2, runs: int = 15, sleep_between: float = 0.25) -> None:
    # Lazy import so --local works even without httpx installed
    from sdk.client import HaldirClient

    print(f"\n=== End-to-end vs {base_url} (warmup {warmup}, runs {runs}) ===")

    client = HaldirClient(api_key=api_key, base_url=base_url)

    # ── create_session ───────────────────────────────────────────────────
    samples = []
    for _ in range(warmup):
        client.create_session(agent_id="bench", scopes=["read", "execute"], spend_limit=1.0)
        time.sleep(sleep_between)
    for _ in range(runs):
        t0 = time.perf_counter()
        session = client.create_session(agent_id="bench", scopes=["read", "execute"], spend_limit=1.0)
        samples.append(time.perf_counter() - t0)
        time.sleep(sleep_between)
    _print("Gate.create_session (REST)", _stats(samples))
    sid = session["session_id"]

    # ── check_permission ─────────────────────────────────────────────────
    samples = []
    for _ in range(warmup):
        client.check_permission(sid, "execute")
        time.sleep(sleep_between)
    for _ in range(runs):
        t0 = time.perf_counter()
        client.check_permission(sid, "execute")
        samples.append(time.perf_counter() - t0)
        time.sleep(sleep_between)
    _print("Gate.check_permission (REST)", _stats(samples))

    # ── log_action (hash-chained write) ──────────────────────────────────
    samples = []
    for _ in range(warmup):
        client.log_action(session_id=sid, tool="bench", action="ping", cost_usd=0.001)
        time.sleep(sleep_between)
    for _ in range(runs):
        t0 = time.perf_counter()
        client.log_action(session_id=sid, tool="bench", action="ping", cost_usd=0.001)
        samples.append(time.perf_counter() - t0)
        time.sleep(sleep_between)
    _print("Watch.log_action (REST)", _stats(samples))

    # ── Full governed-tool envelope: check + log ─────────────────────────
    samples = []
    for _ in range(warmup):
        client.check_permission(sid, "execute")
        client.log_action(session_id=sid, tool="bench", action="ping", cost_usd=0.001)
        time.sleep(sleep_between)
    for _ in range(runs):
        t0 = time.perf_counter()
        client.check_permission(sid, "execute")
        client.log_action(session_id=sid, tool="bench", action="ping", cost_usd=0.001)
        samples.append(time.perf_counter() - t0)
        time.sleep(sleep_between)
    _print("Governed-tool envelope (check+log)", _stats(samples))

    try:
        client.revoke_session(sid)
    except Exception:
        pass


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--local", action="store_true", help="Only run local crypto / hash benchmarks")
    p.add_argument("--base-url", default="https://haldir.xyz")
    p.add_argument("--runs", type=int, default=50)
    args = p.parse_args()

    bench_local(runs=1000)
    if args.local:
        return

    api_key = os.environ.get("HALDIR_API_KEY")
    if not api_key:
        print("\n[skip] HALDIR_API_KEY not set — only local benchmarks were run.")
        print("       export HALDIR_API_KEY=hld_... to run end-to-end benchmarks too.")
        return

    bench_remote(api_key=api_key, base_url=args.base_url, runs=args.runs)


if __name__ == "__main__":
    main()
