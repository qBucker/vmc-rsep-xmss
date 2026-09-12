//! # RSEP-XMSS
//!
//! 可验证单调链（VMC）的生产级实现，实例化为 RSEP-XMSS：
//! 每个 XMSS 签名附带零知识证明，证明签名者的叶子状态沿
//! `FRESH ≺ USED ≺ SPENT` 严格单调推进。
//!
//! ## 设计边界
//!
//! * 域：BN254 标量域 `Fr`。
//! * 证明系统：真实 Groth16（`ark-groth16`）。
//! * Poseidon 常量：Blake2b 确定性派生，**非规范 Grain-LFSR**；
//!   见 [`poseidon`] 模块文档。生产部署应替换为规范向量。
//! * WOTS+：完整 RFC 8391 构造，含 32 字节 ADRS 与位掩码。
//! * 随机源：`OsRng`（生产）或 `ChaCha20Rng`（可复现测试）。

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod adrs;
pub mod errors;
pub mod poseidon;
pub mod state;

pub use ark_bn254::Fr;
pub use errors::RsepError;
pub use state::LeafState;

pub mod circuit;
pub mod proof;
pub mod rsep;
pub mod wots;
pub mod xmss;

pub use crate::rsep::{
    RsepKeyPair, RsepPublicKey, RsepSignature, Verdict, VerifierState,
};
