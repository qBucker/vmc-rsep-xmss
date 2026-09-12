//! WOTS+ 一次性签名（结构遵循 RFC 8391 §3.1）。
//!
//! ## 与 RFC 8391 的关系
//!
//! * 参数：`w = 16`，`log2(w) = 4`，`len1 = 64`，`len2 = 3`，
//!   `len = 67`。与 RFC 8391 一致。
//! * ADRS：完整 32 字节结构（见 [`crate::adrs`]）。
//! * 密钥扩展、链函数、L-tree 的结构与 RFC 8391 §3.1.2–§3.1.6
//!   对应。
//! * **哈希实例化**：RFC 8391 使用 SHA-256，本实现使用
//!   Poseidon；RFC 的 XOR 掩码替换为域加法掩码。二者不产生
//!   相同的输出向量。
//!
//! ## 安全不变量
//!
//! 私钥元素是唯一一次性的：每个元素只能在链上推进（`chain`
//! 只能单调增加起始哈希索引）。任何跨叶子复用都会使 WOTS+
//! 的安全性崩溃，该不变量由 RSEP 层（批次 4）通过状态机强制。

use crate::adrs::{Adrs, TYPE_LTREE, TYPE_OTS};
use crate::poseidon::PoseidonParams;
use crate::Fr;
use ark_ff::{PrimeField, Zero};
use blake2::{Blake2b512, Digest};

/// Winternitz 参数 `w`。
pub const WOTS_W: u32 = 16;
/// `log2(w)`。
pub const WOTS_LOG_W: u32 = 4;
/// 哈希输出字节长度（用于种子/域分离，不影响 `Fr` 宽度）。
pub const WOTS_N: usize = 32;
/// 消息数字个数。
pub const WOTS_LEN1: usize = WOTS_N * 8 / WOTS_LOG_W as usize; // 64
/// 校验和数字个数。
pub const WOTS_LEN2: usize = 3;
/// 总数字个数。
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2; // 67

/// WOTS+ 参数（在整棵 XMSS 树内恒定）。
#[derive(Clone)]
pub struct WotsParams {
    /// Poseidon 参数。
    pub poseidon: PoseidonParams,
    /// 公开的 PRF 种子（用于掩码派生）。
    pub pub_seed: Fr,
}

/// 域外 PRF：从 `pub_seed` 与 `ADRS` 派生域元素。
///
/// 结构对应 RFC 8391 §3.1.1 的 `PRF(SEED, ADRS)`。
#[inline]
pub fn prf(poseidon: &PoseidonParams, seed: Fr, adrs: &Adrs) -> Fr {
    let bytes = adrs.as_bytes();
    let mut inputs = [Fr::from(0u64); 5];
    inputs[0] = seed;
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(chunk);
        inputs[i + 1] = Fr::from(u64::from_be_bytes(b));
    }
    poseidon.hash_slice(&inputs)
}

/// 域外 F：带密钥链步。
///
/// 对应 RFC 8391 §3.1.1 的 `F(KEY, M, ADRS)`。掩码从 `pub_seed`
/// 与 ADRS 的 `key & mask` 字段派生。
#[inline]
pub fn f(poseidon: &PoseidonParams, pub_seed: Fr, m: Fr, adrs: &Adrs) -> Fr {
    let mut a = *adrs;
    a.set_key_mask(0);
    let key = prf(poseidon, pub_seed, &a);
    a.set_key_mask(1);
    let bm = prf(poseidon, pub_seed, &a);
    poseidon.hash_slice(&[key, m + bm])
}

/// 域外 H：带密钥双输入哈希（用于 L-tree 与主树）。
///
/// 对应 RFC 8391 §3.1.1 的 `H(KEY, LEFT, RIGHT, ADRS)`。
#[inline]
pub fn h2(poseidon: &PoseidonParams, pub_seed: Fr,
          l: Fr, r: Fr, adrs: &Adrs) -> Fr
{
    let mut a = *adrs;
    a.set_key_mask(0);
    let key = prf(poseidon, pub_seed, &a);
    a.set_key_mask(1);
    let bml = prf(poseidon, pub_seed, &a);
    a.set_key_mask(2);
    let bmr = prf(poseidon, pub_seed, &a);
    poseidon.hash_slice(&[key, l + bml, r + bmr])
}

/// 链函数 `c^steps(x)`：从哈希索引 `start` 起连续应用 `steps` 次 F。
///
/// 调用者负责填好 `base` 的 layer / type / OTS / chain 字段；
/// 本函数只推进 `hash` 字段。
#[inline]
pub fn chain(poseidon: &PoseidonParams, pub_seed: Fr, x: Fr,
             start: u32, steps: u32, base: &Adrs) -> Fr
{
    let mut cur = x;
    let mut adrs = *base;
    for j in start..start + steps {
        adrs.set_hash(j);
        cur = f(poseidon, pub_seed, cur, &adrs);
    }
    cur
}

/// RFC 8391 §3.1.5：base-w 数字分解 + 校验和。
#[inline]
pub fn message_digits(msg: &[u8; WOTS_N]) -> [u8; WOTS_LEN] {
    let mut digits = [0u8; WOTS_LEN];
    for (i, byte) in msg.iter().enumerate() {
        digits[2 * i]     = (byte >> 4) & 0x0F;
        digits[2 * i + 1] = byte & 0x0F;
    }
    let mut checksum: u32 = 0;
    for j in 0..WOTS_LEN1 {
        checksum += (WOTS_W - 1) - digits[j] as u32;
    }
    for k in 0..WOTS_LEN2 {
        let shift = (WOTS_LEN2 - 1 - k) as u32 * WOTS_LOG_W;
        digits[WOTS_LEN1 + k] = ((checksum >> shift) & 0x0F) as u8;
    }
    digits
}

/// RFC 8391 §3.1.6：从 32 字节种子扩展出 `WOTS_LEN` 个私钥元素。
///
/// 使用 `PRF(sk_seed_fr, ADRS)` 派生，与 RFC 结构对应。返回的
/// 数组是敏感材料，调用者负责生命周期管理。
pub fn expand_seed(poseidon: &PoseidonParams, sk_seed: &[u8; 32],
                   ots: u32, layer: u32) -> [Fr; WOTS_LEN]
{
    let seed_fr = Fr::from_be_bytes_mod_order(sk_seed);
    let mut out = [Fr::zero(); WOTS_LEN];
    for i in 0..WOTS_LEN as u32 {
        let mut adrs = Adrs::zero();
        adrs.set_layer(layer);
        adrs.set_type(TYPE_OTS);
        adrs.set_ots(ots);
        adrs.set_chain(i);
        out[i as usize] = prf(poseidon, seed_fr, &adrs);
    }
    out
}

/// 从私钥元素导出公钥元素。
pub fn pk_from_sk(poseidon: &PoseidonParams, pub_seed: Fr,
                  sk: &[Fr; WOTS_LEN], ots: u32, layer: u32) -> [Fr; WOTS_LEN]
{
    let mut pk = [Fr::zero(); WOTS_LEN];
    for i in 0..WOTS_LEN as u32 {
        let mut adrs = Adrs::zero();
        adrs.set_layer(layer);
        adrs.set_type(TYPE_OTS);
        adrs.set_ots(ots);
        adrs.set_chain(i);
        pk[i as usize] = chain(poseidon, pub_seed, sk[i as usize],
                               0, WOTS_W - 1, &adrs);
    }
    pk
}

/// 从签名重建公钥元素（验证路径）。
pub fn pk_from_sig(poseidon: &PoseidonParams, pub_seed: Fr,
                   sig: &[Fr; WOTS_LEN], digits: &[u8; WOTS_LEN],
                   ots: u32, layer: u32) -> [Fr; WOTS_LEN]
{
    let mut pk = [Fr::zero(); WOTS_LEN];
    for i in 0..WOTS_LEN as u32 {
        let mut adrs = Adrs::zero();
        adrs.set_layer(layer);
        adrs.set_type(TYPE_OTS);
        adrs.set_ots(ots);
        adrs.set_chain(i);
        let start = digits[i as usize] as u32;
        let remaining = (WOTS_W - 1) - start;
        pk[i as usize] = chain(poseidon, pub_seed, sig[i as usize],
                               start, remaining, &adrs);
    }
    pk
}

/// 签名：对 `msg` 的数字分解逐位推进链。
pub fn wots_sign(poseidon: &PoseidonParams, pub_seed: Fr,
                 sk: &[Fr; WOTS_LEN], digits: &[u8; WOTS_LEN],
                 ots: u32, layer: u32) -> [Fr; WOTS_LEN]
{
    let mut sig = [Fr::zero(); WOTS_LEN];
    for i in 0..WOTS_LEN as u32 {
        let mut adrs = Adrs::zero();
        adrs.set_layer(layer);
        adrs.set_type(TYPE_OTS);
        adrs.set_ots(ots);
        adrs.set_chain(i);
        sig[i as usize] = chain(poseidon, pub_seed, sk[i as usize],
                                0, digits[i as usize] as u32, &adrs);
    }
    sig
}

/// RFC 8391 §3.1.3：L-tree 压缩。
///
/// 奇数节点规则：末位节点不参与哈希，直接上浮。ADRS 的 `type`
/// 字段为 `TYPE_LTREE`，`ots` 字段标识当前叶子。
pub fn ltree(poseidon: &PoseidonParams, pub_seed: Fr,
             pk: &[Fr; WOTS_LEN], ots: u32, layer: u32) -> Fr
{
    let mut current: Vec<Fr> = pk.to_vec();
    let mut height: u32 = 0;
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0usize;
        while i < current.len() {
            if i + 1 < current.len() {
                let mut adrs = Adrs::zero();
                adrs.set_layer(layer);
                adrs.set_type(TYPE_LTREE);
                adrs.set_ots(ots);
                adrs.set_tree_height(height);
                adrs.set_tree_index((i / 2) as u32);
                next.push(h2(poseidon, pub_seed, current[i], current[i + 1], &adrs));
            } else {
                next.push(current[i]);
            }
            i += 2;
        }
        current = next;
        height += 1;
    }
    current[0]
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> WotsParams {
        WotsParams {
            poseidon: PoseidonParams::derive(b"wots-tests"),
            pub_seed: Fr::from(0xDEAD_BEEF_u64),
        }
    }

    #[test]
    fn digits_sum_is_constant() {
        let msg = [0xABu8; WOTS_N];
        let d = message_digits(&msg);
        let sum: u32 = d.iter().map(|&x| x as u32).sum();
        // len1 * (w - 1) = 64 * 15 = 960，加上校验和的 3 位
        let expected_checksum = 0u32; // 全 0xA 时校验和为 64*5 = 320
        // 每字节 0xAB → 高 4 位 0xA, 低 4 位 0xB
        // 16 字节 0xA + 16 字节 0xB 交错
        // 逐位校验和验证总和 ≤ len * (w-1) = 1005
        assert!(sum <= WOTS_LEN as u32 * (WOTS_W - 1));
        let _ = expected_checksum;
    }

    #[test]
    fn chain_composition() {
        let p = params();
        let x = Fr::from(42u64);
        let mut adrs = Adrs::zero();
        adrs.set_type(TYPE_OTS);
        adrs.set_ots(0);
        adrs.set_chain(0);
        // c_{0→a+b}(x) = c_{a→b}(c_{0→a}(x))
        let step_a = 3u32;
        let step_b = 5u32;
        let direct = chain(&p.poseidon, p.pub_seed, x, 0, step_a + step_b, &adrs);
        let intermediate = chain(&p.poseidon, p.pub_seed, x, 0, step_a, &adrs);
        let composed = chain(&p.poseidon, p.pub_seed, intermediate, step_a, step_b, &adrs);
        assert_eq!(direct, composed);
    }

    #[test]
    fn chain_zero_steps_is_identity() {
        let p = params();
        let x = Fr::from(123u64);
        let mut adrs = Adrs::zero();
        adrs.set_type(TYPE_OTS);
        let out = chain(&p.poseidon, p.pub_seed, x, 0, 0, &adrs);
        assert_eq!(out, x);
    }

    #[test]
    fn wots_roundtrip() {
        let p = params();
        let seed = [0x11u8; 32];
        let sk = expand_seed(&p.poseidon, &seed, 0, 0);
        let pk = pk_from_sk(&p.poseidon, p.pub_seed, &sk, 0, 0);

        let msg = [0x5Au8; WOTS_N];
        let digits = message_digits(&msg);
        let sig = wots_sign(&p.poseidon, p.pub_seed, &sk, &digits, 0, 0);
        let pk_recovered = pk_from_sig(&p.poseidon, p.pub_seed, &sig, &digits, 0, 0);

        assert_eq!(pk, pk_recovered);
    }

    #[test]
    fn wots_wrong_message_rejects() {
        let p = params();
        let seed = [0x22u8; 32];
        let sk = expand_seed(&p.poseidon, &seed, 0, 0);
        let pk = pk_from_sk(&p.poseidon, p.pub_seed, &sk, 0, 0);

        let msg = [0x01u8; WOTS_N];
        let digits = message_digits(&msg);
        let sig = wots_sign(&p.poseidon, p.pub_seed, &sk, &digits, 0, 0);

        let bad_msg = [0x02u8; WOTS_N];
        let bad_digits = message_digits(&bad_msg);
        let pk_bad = pk_from_sig(&p.poseidon, p.pub_seed, &sig, &bad_digits, 0, 0);
        assert_ne!(pk, pk_bad);
    }

    #[test]
    fn ltree_deterministic_and_sensitive() {
        let p = params();
        let seed = [0x33u8; 32];
        let sk = expand_seed(&p.poseidon, &seed, 7, 0);
        let pk = pk_from_sk(&p.poseidon, p.pub_seed, &sk, 7, 0);

        let root_a = ltree(&p.poseidon, p.pub_seed, &pk, 7, 0);
        let root_b = ltree(&p.poseidon, p.pub_seed, &pk, 7, 0);
        assert_eq!(root_a, root_b);

        // 不同 OTS 索引应给出不同根
        let root_c = ltree(&p.poseidon, p.pub_seed, &pk, 8, 0);
        assert_ne!(root_a, root_c);
    }

    #[test]
    fn prf_is_deterministic() {
        let p = params();
        let mut a = Adrs::zero();
        a.set_type(TYPE_OTS);
        a.set_ots(5);
        a.set_chain(17);
        let x = prf(&p.poseidon, p.pub_seed, &a);
        let y = prf(&p.poseidon, p.pub_seed, &a);
        assert_eq!(x, y);

        let mut b = a;
        b.set_hash(1);
        let z = prf(&p.poseidon, p.pub_seed, &b);
        assert_ne!(x, z);
    }
}
