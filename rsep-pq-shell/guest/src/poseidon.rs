//! Poseidon 置换（rate 2 / capacity 1 / α = 5 / 8 full + 57 partial）。
//!
//! ## 常量派生边界
//!
//! 常量通过 `Blake2b512(b"rsep-xmss-poseidon-v1" || domain || label || idx)`
//! 确定性派生。**这不是规范 Grain-LFSR 派生**：本实现的域外
//! 置换与电路内 gadget 共用同一组参数，因此内部自洽，但不可
//! 与规范 Poseidon 向量互操作。
//!
//! 生产部署应把 [`PoseidonParams::derive`] 替换为从
//! `poseidon-params` crate 或规范参考实现加载的向量；置换和
//! gadget 逻辑无须改动。

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use blake2::{Blake2b512, Digest};

/// 状态宽度。
pub const STATE_WIDTH: usize = 3;
/// 海绵吸收率。
pub const RATE: usize = 2;
/// 容量。
pub const CAPACITY: usize = STATE_WIDTH - RATE;
/// 完整轮数。
pub const FULL_ROUNDS: usize = 8;
/// 部分轮数。
pub const PARTIAL_ROUNDS: usize = 57;
/// S 盒指数。
pub const ALPHA: u64 = 5;

/// Poseidon 参数。
#[derive(Clone, Debug)]
pub struct PoseidonParams {
    /// MDS 矩阵。
    pub mds: [[Fr; STATE_WIDTH]; STATE_WIDTH],
    /// 每轮常量（共 `FULL_ROUNDS + PARTIAL_ROUNDS` 行）。
    pub round_constants: Vec<[Fr; STATE_WIDTH]>,
}

impl PoseidonParams {
    /// 确定性派生参数；见模块级边界声明。
    pub fn derive(domain: &[u8]) -> Self {
        let mut seed = [0u8; 64];
        {
            let mut h = Blake2b512::new();
            h.update(b"rsep-xmss-poseidon-v1");
            h.update(domain);
            seed.copy_from_slice(&h.finalize());
        }

        let mut next = |label: u8, idx: u64| -> Fr {
            let mut h = Blake2b512::new();
            h.update(&seed);
            h.update([label]);
            h.update(idx.to_be_bytes());
            let mut buf = [0u8; 64];
            buf.copy_from_slice(&h.finalize());
            Fr::from_be_bytes_mod_order(&buf)
        };

        let mut mds = [[Fr::from(0u64); STATE_WIDTH]; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                mds[i][j] = next(0x01, (i * STATE_WIDTH + j) as u64);
            }
        }
        let total = FULL_ROUNDS + PARTIAL_ROUNDS;
        let mut round_constants = Vec::with_capacity(total);
        for r in 0..total as u64 {
            let mut row = [Fr::from(0u64); STATE_WIDTH];
            for k in 0..STATE_WIDTH {
                row[k] = next(0x02, r * STATE_WIDTH as u64 + k as u64);
            }
            round_constants.push(row);
        }
        PoseidonParams { mds, round_constants }
    }

    #[inline]
    fn sbox_full(&self, s: &mut [Fr; STATE_WIDTH]) {
        for x in s.iter_mut() {
            let x2 = *x * *x;
            let x4 = x2 * x2;
            *x = x4 * *x;
        }
    }

    #[inline]
    fn sbox_partial(&self, s: &mut [Fr; STATE_WIDTH]) {
        let x = s[0];
        let x2 = x * x;
        let x4 = x2 * x2;
        s[0] = x4 * x;
    }

    #[inline]
    fn mix(&self, s: &mut [Fr; STATE_WIDTH]) {
        let old = *s;
        for i in 0..STATE_WIDTH {
            let mut acc = Fr::from(0u64);
            for j in 0..STATE_WIDTH {
                acc += self.mds[i][j] * old[j];
            }
            s[i] = acc;
        }
    }

    #[inline]
    fn add_rc(&self, s: &mut [Fr; STATE_WIDTH], r: &[Fr; STATE_WIDTH]) {
        for i in 0..STATE_WIDTH {
            s[i] += r[i];
        }
    }

    /// 完整置换。
    pub fn permute(&self, s: &mut [Fr; STATE_WIDTH]) {
        let half = FULL_ROUNDS / 2;
        for r in 0..half {
            self.add_rc(s, &self.round_constants[r]);
            self.sbox_full(s);
            self.mix(s);
        }
        for r in half..half + PARTIAL_ROUNDS {
            self.add_rc(s, &self.round_constants[r]);
            self.sbox_partial(s);
            self.mix(s);
        }
        for r in half + PARTIAL_ROUNDS..FULL_ROUNDS + PARTIAL_ROUNDS {
            self.add_rc(s, &self.round_constants[r]);
            self.sbox_full(s);
            self.mix(s);
        }
    }

    /// 双输入吸收，挤压一个元素。
    pub fn hash2(&self, a: Fr, b: Fr) -> Fr {
        let mut s = [a, b, Fr::zero()];
        self.permute(&mut s);
        s[0]
    }

    /// 变长吸收。
    pub fn hash_slice(&self, inputs: &[Fr]) -> Fr {
        let mut s = [Fr::zero(); STATE_WIDTH];
        let mut i = 0;
        while i + RATE <= inputs.len() {
            for k in 0..RATE {
                s[k] += inputs[i + k];
            }
            self.permute(&mut s);
            i += RATE;
        }
        // 仅当存在非空尾块时才吸收并收尾置换（修复 F1：
        // 整除情形不再多做一次 permutation，
        // 因此 `hash_slice([a, b]) == hash2(a, b)`）。
        if i < inputs.len() {
            for k in 0..inputs.len() - i {
                s[k] += inputs[i + k];
            }
            self.permute(&mut s);
        }
        s[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let p = PoseidonParams::derive(b"test");
        let q = PoseidonParams::derive(b"test");
        assert_eq!(p.hash2(Fr::from(1u64), Fr::from(2u64)),
                   q.hash2(Fr::from(1u64), Fr::from(2u64)));
    }

    #[test]
    fn sensitive_to_domain() {
        let p = PoseidonParams::derive(b"a");
        let q = PoseidonParams::derive(b"b");
        assert_ne!(p.hash2(Fr::from(1u64), Fr::from(2u64)),
                   q.hash2(Fr::from(1u64), Fr::from(2u64)));
    }

    #[test]
    fn not_symmetric() {
        let p = PoseidonParams::derive(b"test");
        assert_ne!(p.hash2(Fr::from(1u64), Fr::from(2u64)),
                   p.hash2(Fr::from(2u64), Fr::from(1u64)));
    }

    #[test]
    fn hash_slice_matches_manual_absorb() {
        let p = PoseidonParams::derive(b"test");
        let a = Fr::from(7u64);
        let b = Fr::from(11u64);
        // 长度为 2 时 hash_slice 应与 hash2 一致（单次 absorb-2 块）
        assert_eq!(p.hash_slice(&[a, b]), p.hash2(a, b));
    }
}
