#!/usr/bin/env python3
"""cusum_dual_mc.py — dual-signal CUSUM Monte Carlo with correlated signals.

Companion to cusum_mc.py (single-signal artifact). Each commit produces two
standardized observations x1, x2.

  H0: (x1, x2) bivariate normal, unit variance, correlation rho.
  H1: both means shift by mu1 (common random numbers: H1 = H0 + mu1).

Per-signal one-sided CUSUM: S_t = max(0, S_{t-1} + x_t - k), k = mu1/2, alarm
when S_t > h. Combination rules:
  single : signal 1 only (baseline)
  OR     : alarm at min(tau1, tau2)        (fast, higher FAR)
  AND    : alarm only if both crossed by T (slower, lower FAR)

Grid: rho in {0, 0.5, 0.8}; h in {4..12}; T = 1e4; N = 1e4 streams per cell;
fixed seed 20260920; vectorized closed-form statistic S_t = C_t - min C_s.

Output: measured FAR Pr(tau <= T | H0) and mean detection delay
E[tau | H1, tau <= T] (censoring fraction in parentheses) per rule/horizon.
"""
import os
import numpy as np

N = int(os.environ.get("CUSUM_N", "10000"))   # streams per cell
T = 10_000          # horizon (commits)
CH = 1000           # stream chunk size (memory bound)
MU1 = 1.0
K = MU1 / 2.0
RHOS = [0.0, 0.5, 0.8, 0.95]
HS = list(range(4, 15))
SEED = 20260920
RULES = ("single", "OR", "AND")


def rule_taus(ta, tb):
    """First-crossing times for the three rules from the two signals' taus."""
    t_and = np.where((ta <= T) & (tb <= T), np.maximum(ta, tb), T + 1)
    return {"single": ta, "OR": np.minimum(ta, tb), "AND": t_and}


def signal_taus(X, hs):
    """First-crossing time per h for one signal via S_t = C_t - min_{s<=t} C_s."""
    C = np.cumsum(X - K, axis=1)
    M = np.minimum.accumulate(
        np.concatenate([np.zeros((C.shape[0], 1)), C], axis=1), axis=1)[:, 1:]
    S = C - M
    out = []
    for h in hs:
        hit = S > h
        any_ = hit.any(axis=1)
        out.append(np.where(any_, hit.argmax(axis=1) + 1, T + 1))
    return out  # list aligned with hs


def main():
    print(f"# dual-signal CUSUM Monte Carlo | N={N} T={T} mu1={MU1} seed={SEED}")
    print("# rules: single = signal 1 only; OR = either crosses; AND = both cross by T")
    for rho in RHOS:
        rng = np.random.default_rng(SEED)
        s = float(np.sqrt(1.0 - rho * rho))
        far = {r: np.zeros(len(HS), dtype=np.int64) for r in RULES}
        dsum = {r: np.zeros(len(HS)) for r in RULES}
        dmiss = {r: np.zeros(len(HS), dtype=np.int64) for r in RULES}
        for _ in range(N // CH):
            Z1 = rng.standard_normal((CH, T))
            Z2 = rng.standard_normal((CH, T))
            X2 = rho * Z1 + s * Z2
            t0 = [signal_taus(Z1, HS), signal_taus(X2, HS)]
            t1 = [signal_taus(Z1 + MU1, HS), signal_taus(X2 + MU1, HS)]
            for i in range(len(HS)):
                r0 = rule_taus(t0[0][i], t0[1][i])
                r1 = rule_taus(t1[0][i], t1[1][i])
                for r in RULES:
                    far[r][i] += int((r0[r] <= T).sum())
                    hit = r1[r] <= T
                    dsum[r][i] += float(r1[r][hit].sum())
                    dmiss[r][i] += int((~hit).sum())
        print(f"\n=== rho={rho:g} ===")
        print("FAR  Pr(tau<=T|H0)")
        print("  h:       " + " ".join(f"{h:>8}" for h in HS))
        for r in RULES:
            cells = []
            for i in range(len(HS)):
                p = far[r][i] / N
                cells.append(f"{p:>8.4f}" if p > 0 else f"{'<1e-4':>8}")
            print(f"  {r:<7}  " + " ".join(cells))
        print("delay E[tau|H1]  (censored fraction)")
        print("  h:       " + " ".join(f"{h:>8}" for h in HS))
        for r in RULES:
            cells = []
            for i in range(len(HS)):
                det = int(N - dmiss[r][i])
                m = dsum[r][i] / det if det else float("nan")
                cens = dmiss[r][i] / N
                cells.append(f"{m:5.1f}({cens:.0%})" if det else "    --   ")
            print(f"  {r:<7}  " + " ".join(f"{c:>8}" for c in cells))


if __name__ == "__main__":
    main()
