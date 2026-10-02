# wf-audit 5 次运行统计（2 核沙盒，cargo 1.98.1，winterfell 0.13.1）

| run | prove_ms | verify_ms | proof_bytes |
|-----|----------|-----------|-------------|
| 1   | 199.3    | 1.035     | 57589 |
| 2   | 244.2    | 1.152     | 57589 |
| 3   | 197.1    | 1.070     | 57589 |
| 4   | 194.6    | 1.038     | 57589 |
| 5   | 197.6    | 1.032     | 57589 |

median: prove 197.6 ms, verify 1.038 ms；proof 57,589 bytes（56.2 KiB，尺寸确定）。
trace build: 0.174 ms。验证门槛 MinConjecturedSecurity(95) 通过（猜想安全，非归约证明）。
语句：C_t = P([C_{t-1}, B_t, DS])[0]，T=32 块，Poseidon-f64（t=3, α=7, 8F+57P，迹 3×4096）。
诚实边界：64 位 Goldilocks 域工程演示（哈希级抗碰撞界弱）；常量 Blake2b 派生非规范；
MDS 伪随机派生未验证 MDS 性质（同仓库 BN254 实例边界）；α=7 因 gcd(7,p-1)=1。
C_T = 0x844ff2e16c353227。
