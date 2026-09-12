//! RSEP-XMSS：VMC 实例化的高层 API。
//!
//! ## 公开输入（5 个，与论文 §4.2 一致）
//!
//! `rho_old`, `rho_new`, `leaf_index`, `c_old`, `c_new`
//!
//! ## 签名捆绑包
//!
//! `RsepSignature` **不含** `v_old / v_new / auth_path`——这些
//! 只存在于证明生成时的 witness。这是本模块相对上一轮审计
//! 的关键修正（问题 3：零知识丢失）。

use ark_ff::PrimeField;
use ark_std::rand::RngCore;
use rand::CryptoRng;

use crate::circuit::RsepCircuit;
use crate::errors::RsepError;
use crate::poseidon::PoseidonParams;
use crate::proof::{
    self, RsepPreparedVk, RsepProof, RsepProvingKey, RsepVerifyingKey,
};
use crate::state::LeafState;
use crate::wots::WOTS_N;
use crate::xmss::{self, XmssPublicKey, XmssSecret, XmssSignature};
use crate::Fr;

/// 公开参数。
#[derive(Clone)]
pub struct RsepPublicKey {
    /// 树高。
    pub h: u8,
    /// XMSS 核心公钥（用于验证 `σ_xmss`）。
    pub xmss_pub: XmssPublicKey,
    /// 状态树初始根（绑定于 `pk`，见论文 §9 的 initial root binding）。
    pub state_root: Fr,
    /// 签名证明的验证密钥。
    pub sign_vk: RsepVerifyingKey,
    /// 签名证明的预处理验证密钥。
    pub sign_pvk: RsepPreparedVk,
    /// 终结证明的验证密钥。
    pub fin_vk: RsepVerifyingKey,
    /// 终结证明的预处理验证密钥。
    pub fin_pvk: RsepPreparedVk,
    /// Poseidon 参数。
    pub poseidon: PoseidonParams,
}

/// 秘密状态。
pub struct RsepKeyPair {
    /// XMSS 密钥（含所有叶子种子）。
    pub xmss: XmssSecret,
    /// 每个叶子的当前状态。
    pub leaf_states: Vec<LeafState>,
    /// 状态树的所有层（`tree[0]` 为叶子层）。
    pub tree: Vec<Vec<Fr>>,
    /// 单调递增计数器。
    pub counter: u64,
    /// 签名证明密钥。
    pub sign_pk: RsepProvingKey,
    /// 终结证明密钥。
    pub fin_pk: RsepProvingKey,
}

/// 公开签名捆绑包。
///
/// **边界声明**：本结构体不含 `auth_path`、`v_old`、`v_new`；
/// 验证器只需要 `(xmss_sig?, leaf_index, proof, new_counter,
/// new_root)` 与自己的 `(cur_root, last_counter)` 即可验证。
#[derive(Clone, Debug)]
pub struct RsepSignature {
    /// XMSS 核心签名；终结时为 `None`。
    pub xmss_sig: Option<XmssSignature>,
    /// 叶子索引。
    pub leaf_index: u64,
    /// Groth16 证明。
    pub proof: RsepProof,
    /// 递增后的计数器。
    pub new_counter: u64,
    /// 新的状态树根。
    pub new_root: Fr,
}

/// 验证结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// 接受；验证器状态已更新。
    Accept,
    /// XMSS 核心签名失败，或终结证明意外携带了 XMSS 签名。
    RejectXmss,
    /// 计数器未严格推进（重放或陈旧签名）。
    RejectStaleCounter,
    /// Groth16 证明被拒。
    RejectProof,
}

// ---------------------------------------------------------------------------
// 密钥生成
// ---------------------------------------------------------------------------

/// 生成密钥对。
///
/// 参数：
/// * `poseidon`：域外 Poseidon 参数；必须与批次 2、3 使用同一
///   派生域，否则电路内与电路外不一致。
/// * `h`：树高，`1 ≤ h ≤ 20`。
/// * `rng`：安全随机源；生产使用 `OsRng`，测试使用
///   `ChaCha20Rng::seed_from_u64`。
pub fn keygen<R: RngCore + CryptoRng>(
    poseidon: &PoseidonParams,
    h: u8,
    rng: &mut R,
) -> Result<(RsepPublicKey, RsepKeyPair), RsepError> {
    assert!((1..=20).contains(&h), "h must be in [1, 20]");
    let n = 1usize << h;

    // 1. XMSS 密钥
    let xmss = XmssSecret::generate(poseidon, h, rng);
    let xmss_pub = xmss.public();

    // 2. 状态树初始化：所有叶子为 Fresh
    let leaf_states = vec![LeafState::Fresh; n];
    let leaves: Vec<Fr> = leaf_states.iter().map(|s| s.to_fr()).collect();
    let tree = build_state_tree(poseidon, leaves);
    let state_root = *tree.last().unwrap().last().unwrap();

    // 3. Groth16 setup：签名电路
    let poseidon_cfg: crate::circuit::poseidon_gadget::PoseidonConfig =
        poseidon.into();
    let sign_template = RsepCircuit {
        poseidon: poseidon_cfg.clone(),
        h: h as usize,
        finalize: false,
        rho_old: Fr::from(0u64),
        rho_new: Fr::from(0u64),
        leaf_index: 0,
        c_old: 0,
        c_new: 1,
        auth_path: vec![Fr::from(0u64); h as usize],
        v_old: LeafState::Fresh.to_fr(),
        v_new: LeafState::Used.to_fr(),
    };
    let (sign_pk, sign_vk) = proof::setup(sign_template, rng)?;
    let sign_pvk = proof::prepare(&sign_vk);

    // 4. Groth16 setup：终结电路
    let fin_template = RsepCircuit {
        poseidon: poseidon_cfg,
        h: h as usize,
        finalize: true,
        rho_old: Fr::from(0u64),
        rho_new: Fr::from(0u64),
        leaf_index: 0,
        c_old: 0,
        c_new: 1,
        auth_path: vec![Fr::from(0u64); h as usize],
        v_old: LeafState::Used.to_fr(),
        v_new: LeafState::Spent.to_fr(),
    };
    let (fin_pk, fin_vk) = proof::setup(fin_template, rng)?;
    let fin_pvk = proof::prepare(&fin_vk);

    let public = RsepPublicKey {
        h,
        xmss_pub,
        state_root,
        sign_vk,
        sign_pvk,
        fin_vk,
        fin_pvk,
        poseidon: poseidon.clone(),
    };
    let secret = RsepKeyPair {
        xmss,
        leaf_states,
        tree,
        counter: 0,
        sign_pk,
        fin_pk,
    };
    Ok((public, secret))
}

fn build_state_tree(poseidon: &PoseidonParams, leaves: Vec<Fr>)
    -> Vec<Vec<Fr>>
{
    let mut layers = vec![leaves.clone()];
    let mut cur = leaves;
    while cur.len() > 1 {
        let mut next = Vec::with_capacity(cur.len() / 2);
        for pair in cur.chunks_exact(2) {
            next.push(poseidon.hash2(pair[0], pair[1]));
        }
        layers.push(next.clone());
        cur = next;
    }
    layers
}

fn update_state_leaf(tree: &mut [Vec<Fr>], index: usize, value: Fr,
                     poseidon: &PoseidonParams)
{
    tree[0][index] = value;
    let mut i = index;
    for level in 0..tree.len() - 1 {
        let parent = i >> 1;
        let l = tree[level][parent * 2];
        let r = tree[level][parent * 2 + 1];
        tree[level + 1][parent] = poseidon.hash2(l, r);
        i = parent;
    }
}

fn auth_path(tree: &[Vec<Fr>], h: usize, index: u64) -> Vec<Fr> {
    let mut path = Vec::with_capacity(h);
    let mut i = index as usize;
    for level in 0..h {
        path.push(tree[level][i ^ 1]);
        i >>= 1;
    }
    path
}

fn current_root(tree: &[Vec<Fr>]) -> Fr {
    *tree.last().unwrap().last().unwrap()
}

// ---------------------------------------------------------------------------
// 签名与终结
// ---------------------------------------------------------------------------

/// 签名（`FRESH → USED`）。
pub fn sign<R: RngCore + CryptoRng>(
    public: &RsepPublicKey,
    secret: &mut RsepKeyPair,
    msg: &[u8; WOTS_N],
    index: u64,
    rng: &mut R,
) -> Result<RsepSignature, RsepError> {
    if index >= (1u64 << public.h) {
        return Err(RsepError::LeafIndexOutOfRange { index, h: public.h });
    }
    if secret.leaf_states[index as usize] != LeafState::Fresh {
        return Err(RsepError::LeafStateMismatch {
            index,
            expected: LeafState::Fresh,
        });
    }

    // 1. XMSS 核心签名
    let xmss_sig = secret.xmss.sign(&public.poseidon, index, msg);

    // 2. 捕获旧路径与旧根
    let path = auth_path(&secret.tree, public.h as usize, index);
    let old_root = current_root(&secret.tree);

    // 3. 状态更新
    update_state_leaf(&mut secret.tree, index as usize,
                      LeafState::Used.to_fr(), &public.poseidon);
    secret.leaf_states[index as usize] = LeafState::Used;
    secret.counter += 1;
    let new_root = current_root(&secret.tree);

    // 4. 生成证明
    let circuit = RsepCircuit {
        poseidon: (&public.poseidon).into(),
        h: public.h as usize,
        finalize: false,
        rho_old: old_root,
        rho_new: new_root,
        leaf_index: index,
        c_old: secret.counter - 1,
        c_new: secret.counter,
        auth_path: path,
        v_old: LeafState::Fresh.to_fr(),
        v_new: LeafState::Used.to_fr(),
    };
    let proof = proof::prove(&secret.sign_pk, circuit, rng)?;

    Ok(RsepSignature {
        xmss_sig: Some(xmss_sig),
        leaf_index: index,
        proof,
        new_counter: secret.counter,
        new_root,
    })
}

/// 终结（`USED → SPENT`）。
pub fn finalize<R: RngCore + CryptoRng>(
    public: &RsepPublicKey,
    secret: &mut RsepKeyPair,
    index: u64,
    rng: &mut R,
) -> Result<RsepSignature, RsepError> {
    if index >= (1u64 << public.h) {
        return Err(RsepError::LeafIndexOutOfRange { index, h: public.h });
    }
    if secret.leaf_states[index as usize] != LeafState::Used {
        return Err(RsepError::LeafStateMismatch {
            index,
            expected: LeafState::Used,
        });
    }

    let path = auth_path(&secret.tree, public.h as usize, index);
    let old_root = current_root(&secret.tree);

    update_state_leaf(&mut secret.tree, index as usize,
                      LeafState::Spent.to_fr(), &public.poseidon);
    secret.leaf_states[index as usize] = LeafState::Spent;
    secret.counter += 1;
    let new_root = current_root(&secret.tree);

    let circuit = RsepCircuit {
        poseidon: (&public.poseidon).into(),
        h: public.h as usize,
        finalize: true,
        rho_old: old_root,
        rho_new: new_root,
        leaf_index: index,
        c_old: secret.counter - 1,
        c_new: secret.counter,
        auth_path: path,
        v_old: LeafState::Used.to_fr(),
        v_new: LeafState::Spent.to_fr(),
    };
    let proof = proof::prove(&secret.fin_pk, circuit, rng)?;

    Ok(RsepSignature {
        xmss_sig: None,
        leaf_index: index,
        proof,
        new_counter: secret.counter,
        new_root,
    })
}

// ---------------------------------------------------------------------------
// 有状态验证器
// ---------------------------------------------------------------------------

/// 验证器状态：`(cur_root, last_counter)`。
///
/// **边界**：论文 §9 明确——`(cur_root, last_counter)` 必须由
/// 验证器自己保护（例如锚定到外部账本）。本结构体不提供持久
/// 化；调用方负责事务性与单调性。
#[derive(Clone)]
pub struct VerifierState {
    /// 当前状态树根。
    pub cur_root: Fr,
    /// 最近接受的计数器。
    pub last_counter: u64,
}

impl VerifierState {
    /// 从公钥初始化。**必须**使用 `public.state_root` 作为初始
    /// 根（论文 §9：initial root binding）。
    pub fn init(public: &RsepPublicKey) -> Self {
        VerifierState {
            cur_root: public.state_root,
            last_counter: 0,
        }
    }

    /// 验证签名转移。
    pub fn verify_signature(
        &mut self,
        public: &RsepPublicKey,
        msg: &[u8; WOTS_N],
        sig: &RsepSignature,
    ) -> Result<Verdict, RsepError> {
        // 1. XMSS 核心签名
        let xmss_sig = sig.xmss_sig.as_ref()
            .ok_or(RsepError::XmssVerifyFailed)?;
        if xmss_sig.leaf_index != sig.leaf_index {
            return Ok(Verdict::RejectXmss);
        }
        if !xmss::xmss_verify(&public.poseidon, &public.xmss_pub,
                              msg, xmss_sig)
        {
            return Ok(Verdict::RejectXmss);
        }

        // 2. 计数器
        if sig.new_counter <= self.last_counter {
            return Ok(Verdict::RejectStaleCounter);
        }

        // 3. Groth16 验证（公开输入仅 5 个）
        let public_inputs = vec![
            self.cur_root,
            sig.new_root,
            Fr::from(sig.leaf_index),
            Fr::from(self.last_counter),
            Fr::from(sig.new_counter),
        ];
        if !proof::verify(&public.sign_pvk, &sig.proof, &public_inputs)? {
            return Ok(Verdict::RejectProof);
        }

        // 4. 更新状态
        self.cur_root = sig.new_root;
        self.last_counter = sig.new_counter;
        Ok(Verdict::Accept)
    }

    /// 验证终结转移（无 XMSS 检查）。
    pub fn verify_finalization(
        &mut self,
        public: &RsepPublicKey,
        sig: &RsepSignature,
    ) -> Result<Verdict, RsepError> {
        if sig.xmss_sig.is_some() {
            return Ok(Verdict::RejectXmss);
        }
        if sig.new_counter <= self.last_counter {
            return Ok(Verdict::RejectStaleCounter);
        }
        let public_inputs = vec![
            self.cur_root,
            sig.new_root,
            Fr::from(sig.leaf_index),
            Fr::from(self.last_counter),
            Fr::from(sig.new_counter),
        ];
        if !proof::verify(&public.fin_pvk, &sig.proof, &public_inputs)? {
            return Ok(Verdict::RejectProof);
        }
        self.cur_root = sig.new_root;
        self.last_counter = sig.new_counter;
        Ok(Verdict::Accept)
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_poseidon() -> PoseidonParams {
        // 必须与电路内、XMSS、状态树使用同一派生域
        PoseidonParams::derive(b"rsep-xmss-test")
    }

    /// 完整往返：keygen → sign → verify。
    #[test]
    fn end_to_end_sign_verify() {
        let poseidon = test_poseidon();
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
        let h = 2u8;
        let (public, mut secret) = keygen(&poseidon, h, &mut rng).unwrap();
        let mut verifier = VerifierState::init(&public);

        let msg = [0x42u8; WOTS_N];
        let sig = sign(&public, &mut secret, &msg, 1, &mut rng).unwrap();
        assert_eq!(sig.leaf_index, 1);
        assert_eq!(sig.new_counter, 1);
        assert!(sig.xmss_sig.is_some());

        match verifier.verify_signature(&public, &msg, &sig).unwrap() {
            Verdict::Accept => {}
            v => panic!("expected Accept, got {:?}", v),
        }
        assert_eq!(verifier.last_counter, 1);
        assert_eq!(verifier.cur_root, sig.new_root);
    }

    /// 重放同一签名被拒（计数器回滚）。
    #[test]
    fn replay_rejected() {
        let poseidon = test_poseidon();
        let mut rng = ChaCha20Rng::seed_from_u64(0xBEEF);
        let (public, mut secret) = keygen(&poseidon, 2, &mut rng).unwrap();
        let mut verifier = VerifierState::init(&public);

        let msg = [0x11u8; WOTS_N];
        let sig = sign(&public, &mut secret, &msg, 0, &mut rng).unwrap();

        assert!(matches!(
            verifier.verify_signature(&public, &msg, &sig).unwrap(),
            Verdict::Accept
        ));
        assert!(matches!(
            verifier.verify_signature(&public, &msg, &sig).unwrap(),
            Verdict::RejectStaleCounter
        ));
    }

    /// 终结（USED → SPENT）。
    #[test]
    fn end_to_end_finalize() {
        let poseidon = test_poseidon();
        let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD);
        let (public, mut secret) = keygen(&poseidon, 2, &mut rng).unwrap();
        let mut verifier = VerifierState::init(&public);

        let msg = [0x55u8; WOTS_N];
        let sig = sign(&public, &mut secret, &msg, 2, &mut rng).unwrap();
        assert!(matches!(
            verifier.verify_signature(&public, &msg, &sig).unwrap(),
            Verdict::Accept
        ));

        let fin = finalize(&public, &mut secret, 2, &mut rng).unwrap();
        assert!(fin.xmss_sig.is_none());
        assert_eq!(fin.new_counter, 2);
        assert!(matches!(
            verifier.verify_finalization(&public, &fin).unwrap(),
            Verdict::Accept
        ));
    }

    /// 终结携带 XMSS 签名被拒。
    #[test]
    fn finalize_with_xmss_rejected() {
        let poseidon = test_poseidon();
        let mut rng = ChaCha20Rng::seed_from_u64(0xAA);
        let (public, mut secret) = keygen(&poseidon, 2, &mut rng).unwrap();
        let mut verifier = VerifierState::init(&public);

        let msg = [0x01u8; WOTS_N];
        let sig = sign(&public, &mut secret, &msg, 0, &mut rng).unwrap();
        // 把签名当作终结提交给 verify_finalization
        assert!(matches!(
            verifier.verify_finalization(&public, &sig).unwrap(),
            Verdict::RejectXmss
        ));
    }

    /// 已使用的叶子再次签名被拒（本地状态检查）。
    #[test]
    fn reuse_leaf_rejected_locally() {
        let poseidon = test_poseidon();
        let mut rng = ChaCha20Rng::seed_from_u64(0x77);
        let (public, mut secret) = keygen(&poseidon, 2, &mut rng).unwrap();
        let msg = [0x22u8; WOTS_N];
        let _ = sign(&public, &mut secret, &msg, 3, &mut rng).unwrap();
        let err = sign(&public, &mut secret, &msg, 3, &mut rng).unwrap_err();
        match err {
            RsepError::LeafStateMismatch { index, expected } => {
                assert_eq!(index, 3);
                assert_eq!(expected, LeafState::Fresh);
            }
            e => panic!("expected LeafStateMismatch, got {:?}", e),
        }
    }

    /// 篡改消息后 XMSS 验证失败。
    #[test]
    fn tampered_message_rejected() {
        let poseidon = test_poseidon();
        let mut rng = ChaCha20Rng::seed_from_u64(0x33);
        let (public, mut secret) = keygen(&poseidon, 2, &mut rng).unwrap();
        let mut verifier = VerifierState::init(&public);

        let msg = [0xAAu8; WOTS_N];
        let sig = sign(&public, &mut secret, &msg, 0, &mut rng).unwrap();

        let bad = [0xBBu8; WOTS_N];
        match verifier.verify_signature(&public, &bad, &sig).unwrap() {
            Verdict::RejectXmss => {}
            v => panic!("expected RejectXmss, got {:?}", v),
        }
        // 状态未变
        assert_eq!(verifier.last_counter, 0);
    }
}
