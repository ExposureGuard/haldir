"""
Micro-benchmarks for Haldir's RFC 6962 Merkle primitives.

Reports throughput (ops/sec) for the three operations on the hot path:
MTH build, inclusion-proof generation, and inclusion-proof verification.
Stdlib-only — no third-party dependency on pytest-benchmark — so it
runs in any environment a customer or auditor wants to double-check.

Run:
    python bench_merkle.py
    python bench_merkle.py --tree-size 100000      # larger trees
    python bench_merkle.py --json                  # machine-readable

Representative results on an M-series MacBook (single core, stdlib
hashlib):

    tree_size=10_000  build=~45ms  inclusion_proof=~200µs  verify=~25µs
    tree_size=100_000 build=~500ms inclusion_proof=~2ms    verify=~30µs

Translation: a tenant with 100k audit entries can get an inclusion
proof in single-digit milliseconds and verify it offline in tens of
microseconds. The verification primitive scales log(n) so even a
100M-entry log is sub-millisecond to verify client-side.
"""

from __future__ import annotations

import argparse
import json as _json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import haldir_merkle as merkle


def _timeit(fn, *, iterations: int) -> dict:
    """Run `fn` `iterations` times, report min/median/p95 per call."""
    times: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    times.sort()
    return {
        "iterations":   iterations,
        "min_s":        times[0],
        "median_s":     statistics.median(times),
        "p95_s":        times[int(0.95 * iterations)] if iterations > 1 else times[-1],
        "max_s":        times[-1],
        "ops_per_sec":  iterations / sum(times) if sum(times) > 0 else float("inf"),
    }


def run(tree_size: int) -> dict:
    """Build a tree of the given size, then benchmark each primitive."""
    # Synthetic leaves — deterministic so re-runs are comparable.
    leaves = [merkle.leaf_hash(f"leaf-{i:08d}".encode()) for i in range(tree_size)]

    # 1) Root build (MTH over the whole tree).
    build = _timeit(lambda: merkle.mth(leaves), iterations=5)

    # 2) Inclusion-proof generation. Sweep through several indices so
    # we don't accidentally measure only the "easy" first-leaf path.
    indices = [0, tree_size // 4, tree_size // 2, 3 * tree_size // 4, tree_size - 1]
    def gen_proof():
        for idx in indices:
            merkle.generate_inclusion_proof(leaves, idx)
    gen = _timeit(gen_proof, iterations=20)
    # Normalize to per-proof.
    for k in ("min_s", "median_s", "p95_s", "max_s"):
        gen[k] /= len(indices)
    gen["ops_per_sec"] *= len(indices)

    # 3) Inclusion-proof verification. Pre-build proofs so we measure
    # verification alone, not proof construction.
    proofs = [merkle.generate_inclusion_proof(leaves, i) for i in indices]
    def verify_batch():
        for p in proofs:
            assert merkle.verify_inclusion_hex(p)
    ver = _timeit(verify_batch, iterations=100)
    for k in ("min_s", "median_s", "p95_s", "max_s"):
        ver[k] /= len(proofs)
    ver["ops_per_sec"] *= len(proofs)

    return {
        "tree_size":          tree_size,
        "mth_build":          build,
        "inclusion_generate": gen,
        "inclusion_verify":   ver,
    }


def _format_human(result: dict) -> str:
    lines = []
    n = result["tree_size"]
    lines.append(f"tree_size = {n:,}")
    lines.append("")
    for label, key in (
        ("MTH build",            "mth_build"),
        ("Inclusion proof gen",  "inclusion_generate"),
        ("Inclusion verify",     "inclusion_verify"),
    ):
        r = result[key]
        lines.append(f"{label:<24}")
        lines.append(f"  median:      {_fmt(r['median_s'])}")
        lines.append(f"  p95:         {_fmt(r['p95_s'])}")
        lines.append(f"  ops/sec:     {r['ops_per_sec']:>12,.0f}")
        lines.append("")
    return "\n".join(lines)


def _fmt(seconds: float) -> str:
    if seconds >= 1:
        return f"{seconds:>8.2f}  s"
    if seconds >= 1e-3:
        return f"{seconds * 1e3:>8.2f} ms"
    if seconds >= 1e-6:
        return f"{seconds * 1e6:>8.2f} µs"
    return f"{seconds * 1e9:>8.2f} ns"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tree-size", type=int, default=10_000,
                    help="Number of leaves (default: 10,000)")
    p.add_argument("--json", action="store_true",
                    help="Emit JSON (for CI / dashboards)")
    args = p.parse_args()

    result = run(args.tree_size)
    if args.json:
        print(_json.dumps(result, indent=2))
    else:
        print(_format_human(result))


if __name__ == "__main__":
    main()
