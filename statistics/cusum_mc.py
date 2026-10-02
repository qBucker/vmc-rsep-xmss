#!/usr/bin/env python3
"""cusum_mc.py — Epochal VMC 判断层 CUSUM 触发器蒙特卡洛（骨架文档 v0.1 §6）

模型：x_t ~ N(mu, 1)，H0: mu=0，H1: mu=mu1（标准化单位）。
CUSUM: S_t = max(0, S_{t-1} + x_t - k)，参考值 k = mu1/2，S_t > h 触发断链报警。
网格：mu1 in {0.5, 1, 2}，h in {2..10}，T in {100, 1000, 10000}，N = 10^4。
公共随机数：H1 样本 = H0 样本 + mu1（同一批噪声，降低对比噪声）。
输出：FAR = P( tau <= T | H0 )；H1 下平均检测延迟 E[tau]，与理论近似 EDD ~ 2h/mu1 对照。
"""
import numpy as np

def cusum_tau(X, k, h):
    """X: (n, T)。返回首次 S_t > h 的时刻（1 起计），未触发返回 T+1。"""
    n, T = X.shape
    tau = np.full(n, T + 1, dtype=np.int64)
    CH = 1000
    for i in range(0, n, CH):
        C = np.cumsum(X[i:i+CH] - k, axis=1)
        M = np.minimum.accumulate(
            np.concatenate([np.zeros((C.shape[0], 1)), C], axis=1), axis=1)[:, 1:]
        S = C - M                      # S_t = C_t - min_{s<=t} C_s（含 C_0=0）
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
        print("FAR  (h 横向): " + " ".join(f"{h:>8}" for h in hs))
        for mu in mus:
            k = mu / 2
            fars = [(cusum_tau(X0, k, h) <= T).mean() for h in hs]
            print(f"  mu={mu:<4} " + " ".join(
                f"{f:>8.4f}" if f > 0 else f"{'<1e-4':>8}" for f in fars))
        print("延迟/理论2h-mu:")
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
