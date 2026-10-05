# VMC/RSEP-XMSS 后量子外壳实测报告

**日期**：2026-09-20 ｜ **执行**：qBucker（沙盒实测）｜ **关联**：VMC v6 论文 §2.3（PQ 迁移路径）、§8（审计链）

## 0. 摘要

把 V6 §2.3 的 PQ 迁移路径从文献级推进到实测级。三条路线，三种证据等级：

| 路线 | 语句 | 结果 | 证据等级 |
|------|------|------|----------|
| **Winterfell 0.13.1 STARK**（对冲轨） | 审计链 C_t = P([C_{t-1}, B_t, DS])[0]，T=32 | prove **197.6 ms** / verify **1.04 ms** / proof **56.2 KiB** | **实测**（本沙盒，5 次中位） |
| **RISC Zero 3.0.6**（保底轨） | C_RSEP 状态迁移电路（与 Groth16 外壳同一 Rust 代码），h=10 | cycles **50,865,966** 实测；单段 prove **5.5 min**、receipt **249.8 KiB**、verify **23.3 ms** 实测；composite 全量 prove ≈22.4 h / receipt ≈60.4 MiB / verify ≈5.6 s（段数线性投影） | **执行层实测 + prove 层实测锚点**（全量 prove 为投影，见 §3） |
| **Lattice Jolt**（a16z，2026-09-09 正式发布） | RV64IMAC zkVM + Akita（Module-SIS） | 65–80 KB 证明、>2M cycles/s（CPU） | **厂商自报，未独立验证**（本沙盒不可构建，见 §4） |

## 1. 关键澄清（论文叙事依据）

Poseidon over BN254 Fr **本身不弱量子**：哈希型原语只有 Grover 对半砍（256→128 bit 级仍成立），BN254 域只是算术载体。当前参考栈中唯一弱量子的组件是 **Groth16 配对层**（Shor）。因此迁移路径 = 换证明系统外壳，电路语句与附录 B 统计核销结论继续有效。zkVM/STARK 路线跑同一 Rust 代码时，全栈 PQ（哈希 PQ + 证明系统 PQ——后者为 believed/plausibly，非归约证明）。

## 2. Winterfell 轨（实测）

### 2.1 语句与 AIR

- 语句取 V6 §8 审计链：C_t = Poseidon([C_{t-1}, B_t, DS])[0]，T=32 块，公开输入 (C_0, C_T)，见证 {B_t} 与中间态。
- Poseidon 实例镜像仓库结构：t=3、8 全轮 + 57 部分轮、常量 Blake2b 派生（label 方案同仓库，域 `rsep-xmss-audit-f64`）；**域为 Goldilocks f64**，α=7（因 gcd(7, p−1)=1；α=5 在 f64 上不可逆，5 | p−1）。
- AIR：迹 3 列 × 4096 行（块 = 128 行：65 轮次行 + 输出行 + idle）；11 条周期列（轮常量 3、S 盒掩码 3、轮门、连续性门 ×2、块首掩码、DS 列）；7 条转移约束（轮约束度 7 + 周期列 [128,128]）；blowup 8（= 约束最小需求）。
- 边界断言：s0 于行 0 = C_0、于末行 = C_T。迹末值与 host 侧独立海绵模拟交叉核对一致（C_T = 0x844ff2e16c353227）。

### 2.2 参数与诚实边界

- ProofOptions：42 queries、blowup 8、grinding 16、二次扩域、FRI fold 4 / remainder 63、Linear batching。
- 验证门槛 `AcceptableOptions::MinConjecturedSecurity(95)` **通过**——这是 Winterfell 的猜想安全估计，非归约证明。
- **工程演示参数，非安全参数集**：64 位域容量有限，以该域做哈希的抗碰撞界弱；常量派生非规范 Grain-LFSR；MDS 为伪随机派生、未验证 MDS 性质（与仓库 BN254 实例同一边界）。安全参数化留作未来工作。

### 2.3 实测数字（2 核沙盒，cargo 1.98.1，winterfell 0.13.1，5 次运行）

| run | prove | verify | proof |
|-----|-------|--------|-------|
| 1 | 199.3 ms | 1.035 ms | 57,589 B |
| 2 | 244.2 ms | 1.152 ms | 57,589 B |
| 3 | 197.1 ms | 1.070 ms | 57,589 B |
| 4 | 194.6 ms | 1.038 ms | 57,589 B |
| 5 | 197.6 ms | 1.032 ms | 57,589 B |

**中位：prove 197.6 ms，verify 1.04 ms；proof 57,589 B（56.2 KiB，尺寸确定）。** 迹构造 0.174 ms。

产物：`out/wf-audit-proof.bin`（sha256 8ddc9823…cd0e81）、`out/wf-bench.txt`、`out/wf-bench-5runs.md`、源码 `wf-audit/`、二进制 `wf-audit-bin`（sha256 db0d8270…534a8f）。

## 3. RISC Zero 轨（保底：执行层实测 + prove 层实测锚点/投影）

### 3.1 语句与构建

- guest：rsep-xmss 电路同一 Rust 代码（`poseidon.rs`/`state.rs` 逐字节复制，仅改导入），h=10，编译为 `riscv32im-risc0-zkvm-elf` ELF（186,076 B，sha256 e086acf4…10f9，已持久化）。nightly + `-Z build-std` + std panicking cfg 补丁（等效 risc0 官方 fork）。
- RZ 3.x 打包：execute/prove 消费的是 ProgramBinary blob（header + user ELF + kernel ELF），kernel 用内置 V1Compat 默认核；打包后 **218,500 B**（sha256 64a34187…2ea9ba16）。
- **image_id = `8b150f91fbe709ad063ea38c0f09bfa3ffa07e4196c1b0e845af78f894113939`**（多次独立复算一致；segment 分片参数不影响 image_id，已验证）。
- host：risc0-zkvm 3.0.6，`prove` + `disable-dev-mode`（真证明）。三大 C++ 内核 crate（keccak/rv32im/recursion sys）vendor 化 + 自定义 build.rs + /mnt 持久 .o 银行。

### 3.2 实测数字（本沙盒 2 核/4GB 无 swap，cargo 1.98.1，risc0-zkvm 3.0.6，dev-mode OFF）

| 指标 | 值 | 口径 |
|------|-----|------|
| execute（cycle 计数） | **2.0–2.2 s** | 实测（4 次一致） |
| total cycles | **50,865,966**（≈50.9M；Poseidon hash2 ≈2.54M cycles/次 × 20） | 实测 |
| segments | **242**（segment_limit_po2=18） | 实测 |
| 单段 prove | **331.3 / 333.6 / 335.6 s**（三段） | 实测（段内 rayon 2 线程） |
| 单段 receipt | **255,842 B**（249.8 KiB，三段一致） | 实测（sha256 a8dc2709…f3e569fc 为 seg-000） |
| 单段 verify_integrity | **23.3 ms**（best of 3，预热后） | 实测 |

**内存边界（实测）**：默认 po2=20（1M cycles/段）单段 trace 即超 4GB 容器硬顶（OOM×2）；po2=18 单段峰值 2.2GB（RSS 实测）。分片只影响 receipt 结构，不改语句、不改 image_id。

**内核优化披露**：初版内核 .o 以 -O0 编译（-O3 巨兽文件编译在该沙盒窗口约束下不可收敛），单段 prove >27 min 未完；重编 -O2 后 5.5 min/段（≈7×）。即使 -O2，数字仍为**本沙盒 2 核保守上界**；cycle 数、receipt 尺寸、verify 正确性与优化等级无关。

### 3.3 投影（段数线性外推，明确标注非全量实测）

| 指标 | 投影值 | 依据 |
|------|--------|------|
| composite prove 总时长 | **≈ 22.4 h** | 242 段 × 332.5 s（三段实测均值） |
| composite receipt | **≈ 61.9 MB**（60.4 MiB） | 242 × 255,842 B + 常数 |
| composite verify | **≈ 5.6 s** | 242 × 23.3 ms + 链式常数 |
| succinct（递归压缩） | 未实测 | lift/join 需约千次递归电路证明，此沙盒（4GB/2 核）工程不可行；厂商口径生产环境（GPU/多核、默认 po2）为分钟级 |

全量 prove 管线已实现**段级断点续传**（每段 receipt 完成即落盘+银行化，回收零损失；`segprove` 工具），三段实测后即按此口径收尾——22.4 h 单沙盒长跑无额外信息价值。

### 3.4 工程状态（复现性讨论素材）

沙盒 /tmp+$HOME 随机整体回收（本会话 20 次）+ /mnt portal 偶发断连。抗回收体系：幂等 recover.sh（工具链/registry/target/内核 .o 全银行化，恢复基线 389 rlib ≈ 4 min）、vendor 化三包内核、recursion_zkr.zip 12 路 Range 并发拉取入银行（S3 单流 34 KB/s 不可行）、delta 增量快照 daemon。

## 4. Lattice Jolt 轨（侦察，厂商自报）

- **状态更新**：Lattice Jolt 已于 **2026-09-09 由 a16z crypto 正式发布**（取代此前 base/lattice 实验分支的认知）。Akita 承诺方案（Module-SIS，LayerZero/CMU/USC/a16z 共同开发，目标 128 bit）。
- 厂商自报：证明 **65–80 KB**（<100 KB，对比哈希型 PQ zkVM 的 200–600 KB）；CPU >2M RV64IMAC cycles/s，Apple Metal GPU >10M；内存 ~200 B/cycle。**未经独立验证。**
- 已知边界：**尚未实现完整零知识**（官方称 companion paper 计划推出）——对 VMC 用途（要 soundness+PQ，不要隐私）可接受，但措辞须如实；QROM 分析在论文中为 future work → 只能说 believed/plausibly PQ。另外 OtterSec 曾披露 Jolt Fiat-Shamir 绑定缺陷（"Unfaithful Claims"，2025-10 至 2026-01 间已修复）——选型风险评估须计入。
- **本沙盒不可实测**：crates.io 无 jolt-sdk/jolt-core（jolt 0.1.0 为 2024 占位空壳）；GitHub 源 ~15 KB/s + S3 不可达，克隆与 guest 工具链安装均不可行。故本轨证据等级封顶为「厂商自报」。

## 5. 论文更新点清单（待 RZ 数字落地后动刀，需用户裁决）

> **状态更新（2026-10-05）**：以下四点已随主机全量复跑落地（数字见 §7）；论文收割
> 全量执行、编译 32 页 0 undefined。清单保留为历史记录（§3.3 投影口径相应作废）。

1. §2.3：PQ 迁移路径段落由「文献指针」升级为「实测背书」——审计链语句已有 STARK 实测（197.6 ms / 1.04 ms / 56.2 KiB，工程演示参数）；C_RSEP 语句的 zkVM 实测（RZ：50.9M cycles、单段 prove 5.5 min / receipt 249.8 KiB / verify 23.3 ms，全量 prove 22.4 h 为投影口径）。
2. 措辞：PQ 侧一律 "believed/plausibly post-quantum"（STARK 哈希型、Akita Module-SIS 均无 QROM 归约闭环）；Winterfell 数字旁标注工程演示参数边界（64 位域）。
3. §6/§7 表格新增「PQ 外壳实测」小节：三路线三等级并列（实测/实测/厂商自报）。
4. 附录：复现指引（wf-audit 与 rsep-pq-shell 源码、ELF/receipt/proof 的 sha256 清单）。

## 6. 复现

```sh
# Winterfell 轨（任一 Linux x86_64，rust ≥1.87）
cd wf-audit && cargo run --release   # 输出 out/wf-audit-proof.bin 与 out/wf-bench.txt

# RISC Zero 轨（本沙盒自愈体系）
sh recover.sh            # 幂等：环境恢复 + 三包内核 vendor + 银行恢复（≈4 min）
sh recompile-o2.sh       # 内核 -O2 重编（断点续传，已完成件自动跳过）
./rsep-pq-host ./rsep-guest.elf exec           # execute/cycles（秒级）
./segprove ./out/program.bin segprove ./segs /mnt/agents/cache/receipts  # 段级 prove
./segprove ./out/program.bin verify1  ./segs   # 单段 verify 实测
./segprove ./out/program.bin assemble ./segs ./out  # 242 段齐后组装 composite receipt
```

## 7. 主机全量复跑（2026-10-05）—— 论文 Table 10 数据源

**取代 §3.3 投影口径**：O2 同构铁律下的全量实测（单会话、零续跑、exit 0、journal 对账通过）。

- **环境**（声明配置入批日志头）：20 核 / 12 GiB 声明（WSL2 `.wslconfig` 冻结）；实机 = 单台 16 GB 消费级笔记本（i7-13650HX）。内核 = 三包 C++ 全 `-O2` 重编（本机版 `recompile-o2.sh`，验收对象 7/8/23 全过）；**guest ELF 不变**（sha256 `e086acf4…`）——cycles/段数语义不变：50,865,966 cycles 与沙盒逐位复现。
- **管线**（`full.rs`）：全 execute → 108 段逐段 prove（逐项 checkpoint）→ lift ×108 → join 树 ×107 → 最终 succinct receipt + `Receipt::new(inner, journal).verify(image_id)` 全覆盖校验；journal 与 host 期望公开输入对账 `journal_ok=true`。
- **shard 定案**：po2=19（108 段），按"稳定配置下峰值 ≤70% 预算"规则（4.59 GiB / 11 GiB ≈ 42%）。

| 指标 | 实测值（主批） | 对照（旧口径） |
|---|---|---|
| execute | 736 ms | |
| user / total cycles | 50,865,966 / 56,623,104 | 与沙盒逐位同 |
| 段 prove ×108 | **median 41.4 s**（38.2–46.5） | O0 4c 525 s/段 → ≈12.9× |
| 段 verify ×108 | mean 12.3 ms（11–14） | 23.3 ms（po2=18 沙盒） |
| lift ×108 | median 7.1 s | O0 67 s |
| join ×107 | median 7.4 s | |
| 段 receipt | 268,066 B（末段 268,182 B = Halted 出口态 +116 B） | po2=18: 255,842 B |
| 最终 receipt | **223,270 B**（succinct；整树常数级） | 投影 60.4 MiB（作废） |
| final verify | **11.5 ms**（full `Receipt::verify`；integrity-only 14.0 ms 进日志不进表） | 投影 5.6 s（作废） |
| 峰值内存 | 4.59 GiB（≤70% 规则 ✓） | O0 4c: 4.58 GiB |
| **端到端 wall** | **99.87 min** | 投影 22.4 h |
| 算账互锁 | 4433.5 + 761.9 + 794.0 + 1.3 + 0.7 s = 5991.5 s ≈ 99.86 min ≡ wall 99.87 ✓ | |

- **+116 B 变体自洽**：段 107（末段）载 Halted 出口态 → 其 lift 及 join 路径 5 节点（r0-53→r1-26→[r2 进位]→r3-6→[r4 进位]→r5-1→r6-0 根）逐位对应树结构。
- **归档**：`measurements/raw/zkvm-full-v1-{run.log,run.rss,timing.csv,report.txt,meta.txt,final.bin}` + `zkvm-o2-recompile.log`；`SHA256SUMS` **52/52 OK**；final.bin sha256 `b4f9fbbf…ce9a3`。
- **复现**：`sh run-full.sh 19 ../rsep-guest.elf`（三级 checkpoint 断点续跑；`meta.txt` 同构守卫——po2/段数/image_id/journal 摘要不匹配即拒跑）。
- **论文状态**：收割 E1–E8 全量落地（摘要 / §3 / Table 10 两行+环境列 / tab:axes / 附录 C / Open Science）；**全文最后一个 "projected" 标签入土**；编译 32 页、0 undefined、1 预存 overfull（tab:scope 3pt，非本批）。
