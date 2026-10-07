#!/usr/bin/env python3
"""cusum_mc.py — Monte Carlo for the CUSUM trigger of the statistical layer.

Model: x_t ~ N(mu, 1); H0: mu = 0; H1: mu = mu1 (standardized units).
CUSUM: S_t = max(0, S_{t-1} + x_t - k), reference value k = mu1/2;
alarm when S_t > h.
Grid: mu1 in {0.5, 1, 2}, h in {2..10}, T in {100, 1000, 10000}, N = 10^4.
Common random numbers: the H1 stream is the H0 stream shifted by mu1
(same noise batch, reducing comparison noise).
Outputs: FAR = P(tau <= T | H0); and mean detection delay E[tau] under H1
against the design approximation EDD ~ 2h/mu1.
"""
import numpy as np

def cusum_tau(X, k, h):
    """X: (n, T). Returns the first t with S_t > h (1-based); T+1 if never."""
    n, T = X.shape
    tau = np.full(n, T + 1, dtype=np.int64)
    CH = 1000
    for i in range(0, n, CH):
        C = np.cumsum(X[i:i+CH] - k, axis=1)
        M = np.minimum.accumulate(
            np.concatenate([np.zeros((C.shape[0], 1)), C], axis=1), axis=1)[:, 1:]
        S = C - M                      # S_t = C_t - min_{s<=t} C_s (with C_0 = 0)
        hit = S > h
        anyhit = hit.any(axis=1)
        tau[i:i+CH] = np.where(anyhit, hit.argmax(axis=1) + 1, T + 1)
    return tau

if __name__ == "__main__":
    rng = np.random.default_rng(20260920)
    N = 10**4
    mus = [0.5, 1.0, 2.0]
    hs = list(range(2, 11))
    Ts = [100, 1000, 10000]

    for T in Ts:
        X0 = rng.standard_normal((N, T))
        print(f"=== T={T} ===")
        print("FAR (h across columns): " + " ".join(f"{h:>8}" for h in hs))
        for mu in mus:
            k = mu / 2
            fars = [(cusum_tau(X0, k, h) <= T).mean() for h in hs]
            print(f"  mu={mu:<4} " + " ".join(
                f"{f:>8.4f}" if f > 0 else f"{'<1e-4':>8}" for f in fars))
        print("delay vs theory 2h/mu:")
        for mu in mus:
            k = mu / 2
            X1 = X0 + mu
            cells = []
            for h in hs:
                tau = cusum_tau(X1, k, h)
                det = tau[tau <= T]
                m = det.mean() if len(det) else float("nan")
                miss = (tau > T).mean()
                cells.append(f"{m:5.1f}/{2*h/mu:<4.1f}{'*' if miss > 0 else ' '}")
            print(f"  mu={mu:<4} " + " ".join(f"{c:>10}" for c in cells))
