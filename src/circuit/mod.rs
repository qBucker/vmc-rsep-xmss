//! RSEP-XMSS 电路层。
//!
//! 实现论文 §4.2 的 `C_RSEP` 关系：
//!
//! ```text
//! 1. MerkleVerify^{H_z}(ρ,  P, i, v_old) = 1
//! 2. MerkleVerify^{H_z}(ρ', P, i, v_new) = 1
//! 3. C_≺(v_old, v_new) = 1
//! 4. v_old = 00₂   (签名) / 01₂ (终结)
//! 5. v_new = 01₂   (签名) / 10₂ (终结)
//! 6. c_new = c_old + 1
//! ```
//!
//! ## 零知识性
//!
//! `auth_path`、`v_old`、`v_new`、索引位均**仅存在于 witness**，
//! 不出现在公开输入中；状态树的内容不会通过证明泄露。
//!
//! ## 约束计数口径
//!
//! 本实现按如下口径统计约束：
//! * Poseidon hash2 = **276** 条（243 基础 = 81 S-box × 3，加 33 条
//!   LC 折叠约束；见论文 §7.1，落在早前 240–300 条/hash2 的估值区间内）。
//! * 严格序比较器主体 = **3** 条乘法（4 条 booleanity 引脚由调用方
//!   施加并计账）。
//! * 位分解、计数器、常量检查按 R1CS 计法逐条计数。
//! * Merkle 路径方向多路复用 = 每级 2 条乘法门（修复 F2 加入）。
//!
//! 在 `h = 10` 时总计 **5,586** 条（口径 `2h·276 + 5h + 16`；含方向
//! mux 的 40 条），由测试 `constraint_count_at_h10` 实测打印。论文
//! §7.2 记录的早前上界估值约 6,041 条，本实现低于该上界。

pub mod comparator;
pub mod merkle_gadget;
pub mod poseidon_gadget;
pub mod rsep;

pub use comparator::{StrictOrderGadget, COMPARATOR_BODY_CONSTRAINTS};
pub use merkle_gadget::MerklePathGadget;
pub use poseidon_gadget::{PoseidonConfig, POSEIDON_BASE_CONSTRAINTS_PER_HASH};
pub use rsep::RsepCircuit;
