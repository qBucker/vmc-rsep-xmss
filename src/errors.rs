//! 统一错误类型。

use crate::state::LeafState;
use thiserror::Error;

/// RSEP-XMSS 错误。
#[derive(Debug, Error)]
pub enum RsepError {
    /// 叶子索引超出 `2^h`。
    #[error("leaf index {index} out of range for height {h}")]
    LeafIndexOutOfRange { index: u64, h: u8 },

    /// 叶子状态与期望不符。
    #[error("leaf {index} state mismatch: expected {expected:?}")]
    LeafStateMismatch { index: u64, expected: LeafState },

    /// 计数器回滚（重放或陈旧根）。
    #[error("counter rollback: offered {offered}, current {current}")]
    CounterRollback { offered: u64, current: u64 },

    /// XMSS 核心签名验证失败。
    #[error("XMSS core verification failed")]
    XmssVerifyFailed,

    /// 转移证明被拒绝。
    #[error("transition proof rejected: {0}")]
    ProofRejected(String),

    /// 证明系统内部错误。
    #[error("proof-system error: {0}")]
    ProofSystem(String),

    /// 序列化错误。
    #[error("serialization error: {0}")]
    Serialization(String),

    /// 根不匹配（验证器状态与签名者状态分歧）。
    #[error("root mismatch")]
    RootMismatch,

    /// 验证密钥与公钥不匹配。
    #[error("verifying key does not match public key")]
    VerifyingKeyMismatch,

    /// 参数不合法。
    #[error("parameter error: {0}")]
    Parameter(String),

    /// 编码非法（长度、位模式或前缀错误）。
    #[error("invalid encoding")]
    InvalidEncoding,
}
