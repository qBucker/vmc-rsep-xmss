# Reproduction Artifact — CUSUM Trigger Monte Carlo (Appendix B)

This package reproduces, with a single command, every Monte Carlo number
reported in the paper *Monotone Accountability: A Foundation for
Verifiable Records and Epoch Transitions* (Appendix B, Tables
`tab:mc-far` and `tab:mc-delay`, and the condensed Table in
Section "The Statistical Layer").

## Contents

- `cusum_mc.py` — the simulation script (self-contained, ~55 lines).
- `expected_output.txt` — reference output produced with the fixed seed.
- `verify.py` — compares a fresh run against the reference, cell by cell.

## Requirements

- Python 3.10+ with NumPy (tested: Python 3.12, NumPy 2.x).
- No other dependencies. Runtime: about a minute on a laptop (≈80 s measured, 2026-10-02; the FAR phase recomputes the statistic once per horizon h).

## One-command reproduction

```bash
python3 cusum_mc.py > my_output.txt
python3 verify.py my_output.txt expected_output.txt
```

`verify.py` exits 0 and prints `ALL CELLS MATCH` if and only if every
FAR cell and every measured/theory delay cell agrees with the reference.

## What is simulated

Standardized observations `x_t ~ N(mu, 1)`; null `mu = 0`, alternative
`mu = mu1`. One-sided CUSUM `S_t = max(0, S_{t-1} + x_t - k)` with reference
value `k = mu1/2`, alarm when `S_t > h`. Grid: `mu1 in {0.5, 1, 2}`,
`h in {2..10}`, `T in {100, 1000, 10000}`, `N = 10^4` streams per cell.
Common random numbers (the H1 stream is the H0 stream shifted by `mu1`)
reduce comparison noise. Fixed seed `20260920` makes every figure
bit-reproducible. The statistic is computed in the vectorized closed form
`S_t = C_t - min_{s<=t} C_s` where `C` is the cumulative sum of `x - k`.

Outputs: FAR `= P(tau <= T | H0)` per cell (paper Table `tab:mc-far`), and
mean detection delay `E[tau | H1]` versus the design approximation
`2h/mu1` (paper Table `tab:mc-delay`; the paper reports the `T = 10000`
rows, where no censoring occurred).

## Dual-signal experiment (`cusum_dual_mc.py`)

Companion Monte Carlo for the correlated two-signal CUSUM frontier, added
2026-10-02. Two standardized, $\rho$-correlated observations per commit;
rules: `single` (baseline), `OR` (either triggers), `AND` (both by $T$).
Grid: $\rho \in \{0, 0.5, 0.8, 0.95\}$, $h \in \{4..14\}$, $T = 10^4$,
$N = 10^4$ streams per cell, seed `20260920`. Reference output:
`dual-output-20261002.txt` (runtime ≈ 40 s). Key reading: at $T = 10^4$,
reaching FAR $\le 1\%$ costs a mean delay of $26.2$ steps for a single
signal vs $21.1$ steps with an OR rule at $\rho = 0$, eroding monotonically
to $25.1$ steps at $\rho = 0.95$; an AND rule reaches the same target in
$24.8$ steps at $\rho = 0$.

## Scope statement (honest boundary)

This artifact covers the **statistical layer only**. The circuit constraint
counts (e.g., 5586 R1CS constraints for the audit relation) and the
STARK/zkVM timings (e.g., 56.3 KiB proofs, 35.8 ms proving at the
canonical operating point) were measured
with the Rust harness in the companion engineering repository
(`github.com/qBucker/vmc-rsep-xmss`); reproducing them requires the
toolchains pinned there (arkworks 0.4, Winterfell 0.13.1, RISC Zero 3.0.6)
and is out of scope for this lightweight package. The theoretical results
(necessity theorem, composition theorem, separation theorem) are proofs,
not experiments.
