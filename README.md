# RSEP-XMSS

可验证单调链（VMC）的生产级实现，实例化为带状态生命周期证明的
XMSS 有状态哈希签名。

> **参考**：J. Zhu, *Monotone Accountability: A Foundation for
> Verifiable Records and Epoch Transitions*（预印本；概念 DOI 始终指向
> 最新版：<https://doi.org/10.5281/zenodo.22987527>）。

## 概述

每个 XMSS 签名附带一个 Groth16 零知识证明，证明签名者的叶子
状态沿链 `FRESH ≺ USED ≺ SPENT` 严格单调推进。验证器不需要
信任签名者的本地状态管理；它检查证明与自己的 `(cur_root,
last_counter)` 是否一致。

## 快速开始

```rust
use rsep_xmss::poseidon::PoseidonParams;
use rsep_xmss::rsep::{self, VerifierState, Verdict};
use rsep_xmss::wots::WOTS_N;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

let poseidon = PoseidonParams::derive(b"my-app");
let mut rng = ChaCha20Rng::seed_from_u64(42);

// 1. 密钥生成（h = 2，4 叶子，演示用）
let (public, mut secret) = rsep::keygen(&poseidon, 2, &mut rng)?;

// 2. 签名
let msg = [0x42u8; WOTS_N];
let sig = rsep::sign(&public, &mut secret, &msg, 0, &mut rng)?;

// 3. 验证
let mut verifier = VerifierState::init(&public);
assert_eq!(verifier.verify_signature(&public, &msg, &sig)?, Verdict::Accept);
```

结构

模块 职责
field BN254 标量域 Fr（经 ark-bn254）
poseidon 域外 Poseidon 置换与参数派生
adrs RFC 8391 §2.5 的 32 字节 ADRS
wots WOTS+ 一次性签名（含 L-tree）
xmss XMSS 核心签名（单层 Merkle 树）
circuit R1CS 电路：Poseidon / Merkle / 比较器 / RSEP
proof Groth16 封装（ark-groth16）
rsep 高层 API：keygen / sign / finalize / VerifierState

与论文的对应

论文元素 实现位置
§3 Syntax rsep::{keygen, sign, finalize, VerifierState}
§3 Security notions VerifierState 的根 + 计数器固定
§3 Definition 1 / Theorem 1 公开根历史（需外部账本锚定）
§3 Instantiation + Appendix C circuit::rsep::RsepCircuit
Appendix C, gate-level circuit circuit::comparator::StrictOrderGadget
Appendix C（transplant 论证） circuit::merkle_gadget::MerklePathGadget
§3（strong termination） tests::full_lifecycle_exhausts_tree
§12 Table 6 + Table 10 benches/rsep.rs

约束计数

本实现的 Poseidon `hash2` 基础约束为 **243 条** R1CS 乘法约束
（81 个 S-box × 3；8 full × 3 + 57 partial × 1），另加 **33 条**
LC 折叠开销（防止部分轮线性组合指数膨胀导致 prover OOM 的
结构性修复，每次折叠 3 条，共 11 次；详见 VERIFICATION.md
第四波记录），实测 **276 条/hash2**（`hash2_lc` 口径，输出绑定
版 `hash2` 为 277 条）。论文附录 C 给出的成本区间为
**240–300 条/hash2**（取决于参数化与域）；本实现含折叠开销
后仍落在区间内，论文附录 C 按上界 300 估值。

`h = 10` 时本实现的实测约束数为 **5,586 条**：

| 项 | 计数 |
|---|---|
| 2 × h × 276（两次 Merkle 验证，含 LC 折叠） | 5,520 |
| Merkle 方向多路复用（每级 2 条 × 双路径） | 40 |
| 索引位分解 + booleanity | 11 |
| 叶子状态两位分解 × 2 | 6 |
| 比较器主体 + 结果绑定 | 4 |
| 常量检查（v_old / v_new） | 2 |
| 计数器线性约束 | 1 |
| Root 绑定 | 2 |
| **合计** | **5,586** |

论文附录 C 按每 hash2 成本上界 300 估值得到 ~6,041 条；
本实现的 5,586 低于该上界估值。差异来源：本实现的 Poseidon
成本为 276/hash2（低于估值上界 300）、计数器用线性约束而非
位分解；Table 2 未单列索引布尔性，本实现单列 11 条
（h booleanity + 1 重构）。

实测以 `circuit/rsep.rs` 的 `constraint_count_at_h10` 测试为准。

本 crate 的论文引用一律以论文正文 PDF 为准；早期文档中曾出现
不存在的章节引用（「§7.2」），已在审计后清除。

安全边界

必读 SECURITY.md。要点：

· 本实现的 Groth16 setup 使用单方随机参数，生产部署必须
替换为 MPC 仪式产物。
· Poseidon 常量使用 Blake2b 派生，非规范 Grain-LFSR。
· VerifierState 的 (cur_root, last_counter) 必须由验证器
  自己保护（如锚定外部账本）；本 crate 不做持久化。
· 签名者的状态更新（counter、tree）必须原子且单调。

编译与测试

```bash
cargo build --release
cargo test --release
cargo bench
```

要求 Rust 1.75+。

许可证

MIT OR Apache-2.0。

