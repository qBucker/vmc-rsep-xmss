//! RSEP `C_RSEP` 语句的 zkVM 原生实现（PQ 外壳实测，RISC Zero STARK）。
//!
//! 与电路版（`src/circuit/rsep.rs`）同一语句：
//!   公开输入：`rho_old, rho_new, leaf_index, c_old, c_new`
//!   见证：`auth_path[h], v_old, v_new`
//!   校验：①② 共享路径双 Merkle 根 ③ 状态严格序 ④ 期望状态常量
//!         ⑤ 计数器 +1
//!
//! Poseidon 参数派生域与仓库 `examples/emit_bitstream.rs` 一致
//! （`rsep-xmss-a2-stats`），即论文附录 B 统计核销的同一实例。
//!
//! 保真说明：`poseidon.rs` / `state.rs` 与 rsep-xmss 仓库逐字节同源，
//! 仅替换导入行（no_std shim：`crate::Fr` → `ark_bn254::Fr`，
//! poseidon.rs 增加 `alloc::vec::Vec`）。算法体零改动。

#![no_main]
#![no_std]

extern crate alloc;

mod poseidon;
mod state;

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use poseidon::PoseidonParams;
use risc0_zkvm::guest::env;
use state::LeafState;

risc0_zkvm::entry!(main);

const POSEIDON_DOMAIN: &[u8] = b"rsep-xmss-a2-stats";

/// 8 个 LE u32 → 32 字节 LE → Fr（输入为规范编码，模约化是恒等）。
fn fr_from_words(w: &[u32; 8]) -> Fr {
    let mut b = [0u8; 32];
    for (i, x) in w.iter().enumerate() {
        b[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
    }
    Fr::from_le_bytes_mod_order(&b)
}

/// Fr → 8 个 LE u32（`into_bigint` 的 4 个 u64 limb 按 LE 展开）。
fn words_from_fr(f: &Fr) -> [u32; 8] {
    let bi = f.into_bigint();
    let mut w = [0u32; 8];
    for i in 0..4 {
        w[2 * i] = bi.0[i] as u32;
        w[2 * i + 1] = (bi.0[i] >> 32) as u32;
    }
    w
}

/// 与 `circuit/merkle_gadget.rs` 同一方向约定：
/// bit = 0 → left = cur, right = sib；bit = 1 → left = sib, right = cur。
fn merkle_root(p: &PoseidonParams, leaf: Fr, index: u64, path: &[Fr]) -> Fr {
    let mut cur = leaf;
    for (level, sib) in path.iter().enumerate() {
        let bit = (index >> level) & 1;
        cur = if bit == 0 {
            p.hash2(cur, *sib)
        } else {
            p.hash2(*sib, cur)
        };
    }
    cur
}

pub fn main() {
    // 头部 8 words: h, finalize, leaf_index(lo,hi), c_old(lo,hi), c_new(lo,hi)
    let mut hdr = [0u32; 8];
    env::read_slice(&mut hdr);
    let h = hdr[0] as usize;
    let finalize = hdr[1];
    let leaf_index = hdr[2] as u64 | ((hdr[3] as u64) << 32);
    let c_old = hdr[4] as u64 | ((hdr[5] as u64) << 32);
    let c_new = hdr[6] as u64 | ((hdr[7] as u64) << 32);

    let mut w = [0u32; 8];
    env::read_slice(&mut w);
    let rho_old = fr_from_words(&w);
    env::read_slice(&mut w);
    let rho_new = fr_from_words(&w);
    env::read_slice(&mut w);
    let v_old = fr_from_words(&w);
    env::read_slice(&mut w);
    let v_new = fr_from_words(&w);

    let mut path = Vec::with_capacity(h);
    for _ in 0..h {
        env::read_slice(&mut w);
        path.push(fr_from_words(&w));
    }

    let params = PoseidonParams::derive(POSEIDON_DOMAIN);

    // 约束 1-2：共享认证路径的双 Merkle 根
    let r_old = merkle_root(&params, v_old, leaf_index, &path);
    let r_new = merkle_root(&params, v_new, leaf_index, &path);
    assert!(r_old == rho_old, "old root mismatch");
    assert!(r_new == rho_new, "new root mismatch");

    // 约束 3-4：状态严格序与期望常量
    let s_old = LeafState::from_fr(v_old).expect("v_old not a state");
    let s_new = LeafState::from_fr(v_new).expect("v_new not a state");
    let (exp_old, exp_new) = if finalize == 1 {
        (LeafState::Used, LeafState::Spent)
    } else {
        (LeafState::Fresh, LeafState::Used)
    };
    assert!(s_old == exp_old && s_new == exp_new, "state constants mismatch");
    assert!(s_old.strict_lt(s_new), "not strictly monotone");

    // 约束 5：计数器严格推进
    assert!(c_new == c_old + 1, "counter must advance by exactly 1");

    // 提交公开输入（22 words = rho_old, rho_new, leaf_index, c_old, c_new）
    let mut out = [0u32; 22];
    out[0..8].copy_from_slice(&words_from_fr(&rho_old));
    out[8..16].copy_from_slice(&words_from_fr(&rho_new));
    out[16] = leaf_index as u32;
    out[17] = (leaf_index >> 32) as u32;
    out[18] = c_old as u32;
    out[19] = (c_old >> 32) as u32;
    out[20] = c_new as u32;
    out[21] = (c_new >> 32) as u32;
    env::commit_slice(&out);
}
