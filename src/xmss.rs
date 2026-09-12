//! XMSS 核心（单层 Merkle 树，高度 `h ≤ 20`）。
//!
//! 本模块实现 RFC 8391 §4.1 的单层 XMSS，用于 RSEP 的状态树
//! 之外的另一棵独立树：XMSS 签名本身的 Merkle 树。叶子状态树
//! 由批次 4 的 `rsep` 模块负责。
//!
//! ## 边界
//!
//! * 单层：不实现超树（`d > 1`）。论文 §4 使用单层，与之对应。
//! * 哈希：Poseidon（同上）。
//! * `sk_seeds` 用 `Zeroizing` 包裹，`drop` 时零化。

use crate::adrs::{Adrs, TYPE_HASH_TREE};
use crate::poseidon::PoseidonParams;
use crate::wots::{
    self, expand_seed, h2, ltree, message_digits, pk_from_sk, pk_from_sig,
    wots_sign, WOTS_LEN, WOTS_N,
};
use crate::Fr;
use ark_ff::Zero;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// XMSS 公开密钥。
#[derive(Clone, Debug)]
pub struct XmssPublicKey {
    /// 树高。
    pub h: u8,
    /// 公开种子（用于掩码派生）。
    pub pub_seed: Fr,
    /// Merkle 根。
    pub root: Fr,
}

/// XMSS 签名。
#[derive(Clone, Debug)]
pub struct XmssSignature {
    /// 叶子索引。
    pub leaf_index: u64,
    /// WOTS+ 签名元素。
    pub wots_sig: [Fr; WOTS_LEN],
    /// 认证路径，长度 `h`。
    pub auth_path: Vec<Fr>,
}

/// XMSS 秘密状态。
///
/// 注意：本结构体持有全部叶子的种子；生产部署应改为按需派生
/// 并对索引做严格单调校验（RSEP 层通过状态树保证）。
pub struct XmssSecret {
    /// 树高。
    pub h: u8,
    /// 公开种子。
    pub pub_seed: Fr,
    /// 每个叶子对应的 32 字节种子。
    pub sk_seeds: Zeroizing<Vec<[u8; 32]>>,
    /// 自下而上的所有层（`tree[0]` 为叶子层，`tree[h]` 为根层）。
    pub tree: Vec<Vec<Fr>>,
}

impl XmssSecret {
    /// 从 CSPRNG 生成。
    pub fn generate<R: RngCore + CryptoRng>(
        poseidon: &PoseidonParams, h: u8, rng: &mut R,
    ) -> Self {
        assert!(h >= 1 && h <= 20, "h must be in [1, 20]");
        let n = 1usize << h;
        let pub_seed = Fr::from(rng.next_u64());

        let mut sk_seeds = Vec::with_capacity(n);
        let mut leaves = Vec::with_capacity(n);
        for i in 0..n {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            let wots_sk = expand_seed(poseidon, &s, i as u32, 0);
            let wots_pk = pk_from_sk(poseidon, pub_seed, &wots_sk, i as u32, 0);
            leaves.push(ltree(poseidon, pub_seed, &wots_pk, i as u32, 0));
            sk_seeds.push(s);
        }

        let tree = build_tree(poseidon, pub_seed, &leaves, 0);
        XmssSecret {
            h,
            pub_seed,
            sk_seeds: Zeroizing::new(sk_seeds),
            tree,
        }
    }

    /// 导出公开密钥。
    pub fn public(&self) -> XmssPublicKey {
        XmssPublicKey {
            h: self.h,
            pub_seed: self.pub_seed,
            root: *self.tree.last().unwrap().last().unwrap(),
        }
    }

    /// 签名。
    ///
    /// **调用者必须保证每个 `index` 至多使用一次**——本函数自身
    /// 不做状态检查，由 RSEP 层通过状态树强制。
    pub fn sign(&self, poseidon: &PoseidonParams, index: u64,
                msg: &[u8; WOTS_N]) -> XmssSignature
    {
        assert!((index as usize) < self.sk_seeds.len(),
                "leaf index out of range");
        let wots_sk = expand_seed(poseidon, &self.sk_seeds[index as usize],
                                  index as u32, 0);
        let digits = message_digits(msg);
        let wots_sig = wots_sign(poseidon, self.pub_seed, &wots_sk, &digits,
                                 index as u32, 0);
        let auth_path = self.auth_path(index);
        XmssSignature {
            leaf_index: index,
            wots_sig,
            auth_path,
        }
    }

    /// 叶子索引的认证路径。
    pub fn auth_path(&self, index: u64) -> Vec<Fr> {
        let mut path = Vec::with_capacity(self.h as usize);
        let mut i = index as usize;
        for level in 0..self.h as usize {
            path.push(self.tree[level][i ^ 1]);
            i >>= 1;
        }
        path
    }
}

/// 从叶子层自下而上构建 Merkle 树，返回所有层。
///
/// `layer` 与 `tree` 字段在 ADRS 中固定为 0（单层树）。
pub fn build_tree(poseidon: &PoseidonParams, pub_seed: Fr,
                  leaves: &[Fr], layer: u32) -> Vec<Vec<Fr>>
{
    assert!(leaves.len().is_power_of_two() && !leaves.is_empty());
    let mut layers = Vec::with_capacity(leaves.len().trailing_zeros() as usize + 1);
    layers.push(leaves.to_vec());
    let mut cur = leaves.to_vec();
    let mut height: u32 = 0;
    while cur.len() > 1 {
        let mut next = Vec::with_capacity(cur.len() / 2);
        for (i, pair) in cur.chunks_exact(2).enumerate() {
            let mut adrs = Adrs::zero();
            adrs.set_layer(layer);
            adrs.set_tree(0);
            adrs.set_type(TYPE_HASH_TREE);
            adrs.set_tree_height(height);
            adrs.set_tree_index(i as u32);
            next.push(h2(poseidon, pub_seed, pair[0], pair[1], &adrs));
        }
        layers.push(next.clone());
        cur = next;
        height += 1;
    }
    layers
}

/// 验证 XMSS 签名。
pub fn xmss_verify(poseidon: &PoseidonParams, pub_key: &XmssPublicKey,
                   msg: &[u8; WOTS_N], sig: &XmssSignature) -> bool
{
    if sig.auth_path.len() != pub_key.h as usize {
        return false;
    }
    if sig.leaf_index >= (1u64 << pub_key.h) {
        return false;
    }

    let digits = message_digits(msg);
    let wots_pk = pk_from_sig(poseidon, pub_key.pub_seed, &sig.wots_sig,
                              &digits, sig.leaf_index as u32, 0);
    let leaf = ltree(poseidon, pub_key.pub_seed, &wots_pk,
                     sig.leaf_index as u32, 0);

    let mut cur = leaf;
    let mut i = sig.leaf_index as usize;
    for (level, sib) in sig.auth_path.iter().enumerate() {
        let mut adrs = Adrs::zero();
        adrs.set_layer(0);
        adrs.set_tree(0);
        adrs.set_type(TYPE_HASH_TREE);
        adrs.set_tree_height(level as u32);
        adrs.set_tree_index((i >> 1) as u32);

        cur = if i & 1 == 0 {
            h2(poseidon, pub_key.pub_seed, cur, *sib, &adrs)
        } else {
            h2(poseidon, pub_key.pub_seed, *sib, cur, &adrs)
        };
        i >>= 1;
    }
    cur == pub_key.root
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn poseidon() -> PoseidonParams {
        PoseidonParams::derive(b"xmss-tests")
    }

    #[test]
    fn sign_verify_roundtrip_small() {
        let p = poseidon();
        let mut rng = OsRng;
        let sk = XmssSecret::generate(&p, 4, &mut rng);
        let pk = sk.public();

        let msg = [0x42u8; WOTS_N];
        for i in 0..16u64 {
            let sig = sk.sign(&p, i, &msg);
            assert!(xmss_verify(&p, &pk, &msg, &sig), "leaf {} failed", i);
        }
    }

    #[test]
    fn wrong_index_rejected() {
        let p = poseidon();
        let mut rng = OsRng;
        let sk = XmssSecret::generate(&p, 4, &mut rng);
        let pk = sk.public();

        let msg = [0x01u8; WOTS_N];
        let mut sig = sk.sign(&p, 3, &msg);
        sig.leaf_index = 5;
        assert!(!xmss_verify(&p, &pk, &msg, &sig));
    }

    #[test]
    fn tampered_message_rejected() {
        let p = poseidon();
        let mut rng = OsRng;
        let sk = XmssSecret::generate(&p, 4, &mut rng);
        let pk = sk.public();

        let msg = [0xAAu8; WOTS_N];
        let sig = sk.sign(&p, 0, &msg);
        let bad = [0xBBu8; WOTS_N];
        assert!(!xmss_verify(&p, &pk, &bad, &sig));
    }

    #[test]
    fn tree_height_matches() {
        let p = poseidon();
        let mut rng = OsRng;
        for h in [1u8, 2, 3, 4] {
            let sk = XmssSecret::generate(&p, h, &mut rng);
            assert_eq!(sk.tree.len(), h as usize + 1);
            assert_eq!(sk.tree[h as usize].len(), 1);
            for (lvl, layer) in sk.tree.iter().enumerate() {
                assert_eq!(layer.len(), 1usize << (h as usize - lvl),
                           "level {} size mismatch for h={}", lvl, h);
            }
        }
    }

    #[test]
    fn auth_path_length() {
        let p = poseidon();
        let mut rng = OsRng;
        let sk = XmssSecret::generate(&p, 5, &mut rng);
        for i in 0..32u64 {
            assert_eq!(sk.auth_path(i).len(), 5);
        }
    }
}
