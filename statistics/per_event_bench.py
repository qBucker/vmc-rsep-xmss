#!/usr/bin/env python3
"""Per-event microbenchmark of the statistical layer (reference artifact).

Measures the per-event CUSUM update as used in the paper's scope table:

    S_t = max(0, S_{t-1} + x_t - mu0 - k)        (mu0 = 0)

Two forms:
  1. scalar loop  — the deployed per-event form (one update at a time);
  2. vectorized numpy — the bulk form used by cusum_mc.py
     (S = cumsum - running min), amortized per element.

Interpreted Python is an UPPER BOUND for a compiled deployment; the paper
labels these numbers "measured (Python reference; upper bound)".

Usage: python3 statistics/per_event_bench.py [n_scalar] [n_streams] [T]
Defaults: n_scalar = 2_000_000, n_streams = 200, T = 10_000.
"""
import random
import sys
import time


def scalar_bench(n: int) -> float:
    """ns per update, scalar form S = max(0, S + x - k)."""
    k = 0.5
    xs = [random.gauss(0.5, 1.0) for _ in range(1024)]
    s = 0.0
    t0 = time.perf_counter()
    for i in range(n):
        x = xs[i & 1023]
        s = max(0.0, s + x - k)
    dt = time.perf_counter() - t0
    # keep the accumulator observable
    if s > 1e9:
        raise RuntimeError("unreachable")
    return dt / n * 1e9


def vectorized_bench(n_streams: int, T: int) -> float:
    """ns per element, vectorized form (amortized, cusum_mc.py style)."""
    import numpy as np

    rng = np.random.default_rng(20260920)
    X = rng.standard_normal((n_streams, T)) + 0.5
    k = 0.5
    t0 = time.perf_counter()
    C = np.cumsum(X - k, axis=1)
    M = np.minimum.accumulate(
        np.concatenate([np.zeros((n_streams, 1)), C], axis=1), axis=1
    )[:, 1:]
    S = C - M
    dt = time.perf_counter() - t0
    if S.shape != (n_streams, T):
        raise RuntimeError("unreachable")
    return dt / (n_streams * T) * 1e9


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2_000_000
    ns = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    T = int(sys.argv[3]) if len(sys.argv) > 3 else 10_000

    print(f"# per-event microbench (python {sys.version.split()[0]})")
    print("# scalar: S = max(0, S + x - k); vectorized: S = cumsum - running min")
    scalar_bench(200_000)  # warmup
    print(f"scalar_ns_per_update: {scalar_bench(n):.1f}  # n={n}")
    print(f"numpy_ns_per_elem: {vectorized_bench(ns, T):.2f}  # {ns} streams x T={T}")


if __name__ == "__main__":
    main()
