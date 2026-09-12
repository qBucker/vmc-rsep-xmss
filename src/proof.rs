//! Groth16 封装（`ark-groth16` 0.4，BN254）。
//!
//! ## 接口对齐
//!
//! * `setup` 接收电路模板，返回 `(pk, vk)`。
//! * `prepare` 把 `vk` 预处理为 `PreparedVerifyingKey`，可复用。
//! * `prove` 接收电路实例与 `pk`，返回 `Proof<Bn254>`。
//! * `verify` 接收 `PreparedVerifyingKey`、`proof` 与**公开输入
//!   向量**——**不接收 witness**。
//!
//! ## 可信设置边界
//!
//! `setup` 使用 `generate_random_parameters_with_reduction`，即
//! **单方随机参数**。生产部署必须替换为 MPC 仪式生成的参数
//! （否则参数生成者持有 trapdoor，可伪造任意证明）。本模块
//! 提供 `setup_with_params` 接受外部参数，但仪式本身不在本
//! crate 范围内。

use ark_bn254::{Bn254, Fr};
use ark_groth16::{
    r1cs_to_qap::LibsnarkReduction, Groth16, PreparedVerifyingKey, Proof,
    ProvingKey, VerifyingKey,
};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;

use crate::circuit::RsepCircuit;
use crate::errors::RsepError;

/// Groth16 证明（BN254）。
pub type RsepProof = Proof<Bn254>;
/// 证明密钥。
pub type RsepProvingKey = ProvingKey<Bn254>;
/// 验证密钥。
pub type RsepVerifyingKey = VerifyingKey<Bn254>;
/// 预处理验证密钥。
pub type RsepPreparedVk = PreparedVerifyingKey<Bn254>;

/// 执行 Groth16 setup。
///
/// **安全警告**：本函数生成单方随机参数。生产部署不得直接
/// 使用；应以 MPC 仪式产物初始化 `RsepProvingKey` /
/// `RsepVerifyingKey` 后通过 `pk_from_bytes` / `vk_from_bytes`
/// 加载。
pub fn setup<R: RngCore>(
    circuit: RsepCircuit,
    rng: &mut R,
) -> Result<(RsepProvingKey, RsepVerifyingKey), RsepError> {
    let pk = Groth16::<Bn254, LibsnarkReduction>
        ::generate_random_parameters_with_reduction(circuit, rng)
        .map_err(|e| RsepError::ProofSystem(format!("setup: {e}")))?;
    let vk = pk.vk.clone();
    Ok((pk, vk))
}

/// 预处理验证密钥。
pub fn prepare(vk: &RsepVerifyingKey) -> RsepPreparedVk {
    vk.clone().into()
}

/// 生成证明。
pub fn prove<R: RngCore>(
    pk: &RsepProvingKey,
    circuit: RsepCircuit,
    rng: &mut R,
) -> Result<RsepProof, RsepError> {
    Groth16::<Bn254, LibsnarkReduction>
        ::create_random_proof_with_reduction(circuit, pk, rng)
        .map_err(|e| RsepError::ProofSystem(format!("prove: {e}")))
}

/// 验证证明。**只接收公开输入**，不含 witness。
pub fn verify(
    pvk: &RsepPreparedVk,
    proof: &RsepProof,
    public_inputs: &[Fr],
) -> Result<bool, RsepError> {
    Groth16::<Bn254, LibsnarkReduction>
        ::verify_proof(pvk, proof, public_inputs)
        .map_err(|e| RsepError::ProofSystem(format!("verify: {e}")))
}

// ---------------------------------------------------------------------------
// 序列化
// ---------------------------------------------------------------------------

/// 序列化证明为压缩字节串。
pub fn proof_to_bytes(p: &RsepProof) -> Result<Vec<u8>, RsepError> {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf)
        .map_err(|e| RsepError::Serialization(format!("proof: {e}")))?;
    Ok(buf)
}

/// 反序列化证明。
pub fn proof_from_bytes(b: &[u8]) -> Result<RsepProof, RsepError> {
    RsepProof::deserialize_compressed(b)
        .map_err(|e| RsepError::Serialization(format!("proof: {e}")))
}

/// 序列化验证密钥。
pub fn vk_to_bytes(vk: &RsepVerifyingKey) -> Result<Vec<u8>, RsepError> {
    let mut buf = Vec::new();
    vk.serialize_compressed(&mut buf)
        .map_err(|e| RsepError::Serialization(format!("vk: {e}")))?;
    Ok(buf)
}

/// 反序列化验证密钥。
pub fn vk_from_bytes(b: &[u8]) -> Result<RsepVerifyingKey, RsepError> {
    RsepVerifyingKey::deserialize_compressed(b)
        .map_err(|e| RsepError::Serialization(format!("vk: {e}")))
}
