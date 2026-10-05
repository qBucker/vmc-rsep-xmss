//! 递归聚合冒烟 v2 —— 真实段 receipt + 显式递归聚合（用户方案逐字版）。
//!
//! 流程: 全量 execute（~2 s）→ server.prove_segment 前 n 段 → lift ×n →
//!       join 树 → 最终 succinct receipt（+ verify）。
//! 验证三件事: (a) 递归 API 可用（lift/join 跑通即证）; (b) 单层递归内存峰值（VmHWM 逐步打印）;
//!             (c) 最终 receipt 尺寸量级;  (d) shard 决策: 不同 segment_po2 对比。
//!
//! 用法: smoke <guest.elf> <segment_po2> <n_segments>
//! 产出: out/smoke-v2-po2<P>-n<N>.txt + out/receipt-succinct-smoke-v2-po2<P>.bin

use std::io::Read as _;
use std::time::Instant;

extern crate alloc;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use risc0_zkvm::{
    get_prover_server,
    recursion::{join, lift},
    ExecutorEnv, ExecutorImpl, ProverOpts, ReceiptClaim, SuccinctReceipt, VerifierContext,
};

#[path = "../../../guest/src/poseidon.rs"]
mod poseidon;
#[path = "../../../guest/src/state.rs"]
mod state;

use poseidon::PoseidonParams;

const POSEIDON_DOMAIN: &[u8] = b"rsep-xmss-a2-stats";
const H: usize = 10;
const LEAF_INDEX: u64 = 3;
const C_OLD: u64 = 41;

fn words_from_fr(f: &Fr) -> [u32; 8] {
    let bi = f.into_bigint();
    let mut w = [0u32; 8];
    for i in 0..4 {
        w[2 * i] = bi.0[i] as u32;
        w[2 * i + 1] = (bi.0[i] >> 32) as u32;
    }
    w
}

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

fn build_tree(p: &PoseidonParams, leaves: &[Fr]) -> (Fr, Vec<Vec<Fr>>) {
    let mut layers = vec![leaves.to_vec()];
    let mut cur = leaves.to_vec();
    while cur.len() > 1 {
        let mut next = Vec::with_capacity(cur.len() / 2);
        for pair in cur.chunks(2) {
            next.push(p.hash2(pair[0], pair[1]));
        }
        layers.push(next.clone());
        cur = next;
    }
    (cur[0], layers)
}

fn vm_hwm_kb() -> u64 {
    let mut s = String::new();
    let _ = std::fs::File::open("/proc/self/status").and_then(|mut f| f.read_to_string(&mut s));
    s.lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let elf_path = args.get(1).cloned().unwrap_or_else(|| "rsep-guest.elf".into());
    let po2: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(18);
    let nseg: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);

    // ---- 见证构造（与 host/main.rs 相同）----
    let params = PoseidonParams::derive(POSEIDON_DOMAIN);
    let n = 1usize << H;
    let mut leaves = vec![Fr::from(0u64); n];
    let (rho_old, layers) = build_tree(&params, &leaves);
    let mut path = Vec::with_capacity(H);
    let mut i = LEAF_INDEX as usize;
    for level in 0..H {
        path.push(layers[level][i ^ 1]);
        i >>= 1;
    }
    let v_old = Fr::from(0u64);
    let v_new = Fr::from(1u64);
    leaves[LEAF_INDEX as usize] = v_new;
    let (rho_new, _) = build_tree(&params, &leaves);
    let c_new = C_OLD + 1;
    assert_eq!(merkle_root(&params, v_old, LEAF_INDEX, &path), rho_old);
    assert_eq!(merkle_root(&params, v_new, LEAF_INDEX, &path), rho_new);

    let mut words: Vec<u32> = vec![
        H as u32,
        0,
        LEAF_INDEX as u32,
        (LEAF_INDEX >> 32) as u32,
        C_OLD as u32,
        (C_OLD >> 32) as u32,
        c_new as u32,
        (c_new >> 32) as u32,
    ];
    for f in [&rho_old, &rho_new, &v_old, &v_new] {
        words.extend_from_slice(&words_from_fr(f));
    }
    for sib in &path {
        words.extend_from_slice(&words_from_fr(sib));
    }

    let user_elf = std::fs::read(&elf_path).expect("read guest elf");
    let binary = risc0_binfmt::ProgramBinary::new(&user_elf, risc0_zkos_v1compat::V1COMPAT_ELF);
    let image_id = binary.compute_image_id().expect("image id");
    let elf = binary.encode();
    println!(
        "smoke-v2: elf={} | segment_po2={} | n_segments={} | image_id={}",
        elf_path, po2, nseg, image_id
    );

    // ---- 1. 全量执行（拿真 session）----
    let env = ExecutorEnv::builder()
        .write_slice(&words)
        .segment_limit_po2(po2)
        .build()
        .expect("env");
    let t = Instant::now();
    let session = ExecutorImpl::from_elf(env, &elf)
        .expect("executor")
        .run()
        .expect("execute");
    println!(
        "execute: {} ms | total segments={} | VmHWM={} KB",
        t.elapsed().as_millis(),
        session.segments.len(),
        vm_hwm_kb()
    );

    let ctx = VerifierContext::default();
    let server = get_prover_server(&ProverOpts::default()).expect("prover server");

    // ---- 2. 证明前 n 段（真实段 receipt）----
    let mut seg_receipts: Vec<risc0_zkvm::SegmentReceipt> = Vec::new();
    for idx in 0..nseg.min(session.segments.len()) {
        let seg = session.segments[idx].resolve().expect("resolve segment");
        let t = Instant::now();
        let rct = server.prove_segment(&ctx, &seg).expect("prove segment");
        let ms = t.elapsed().as_millis();
        let bytes = bincode::serialize(&rct).expect("ser").len();
        println!(
            "seg {idx}: prove {ms} ms | receipt {bytes} B | segments_total={} | VmHWM {} KB",
            session.segments.len(),
            vm_hwm_kb()
        );
        seg_receipts.push(rct);
    }
    drop(session);

    // ---- 3. lift ×n ----
    let t_all = Instant::now();
    let mut level: Vec<SuccinctReceipt<ReceiptClaim>> = Vec::new();
    for (idx, rct) in seg_receipts.iter().enumerate() {
        let t = Instant::now();
        let s = lift(rct).expect("lift");
        println!(
            "lift {idx}: {} ms | receipt {} B | VmHWM {} KB",
            t.elapsed().as_millis(),
            bincode::serialize(&s).expect("ser").len(),
            vm_hwm_kb()
        );
        level.push(s);
    }

    // ---- 4. join 树（配对 + 进位）----
    let mut round = 0usize;
    while level.len() > 1 {
        let mut next: Vec<SuccinctReceipt<ReceiptClaim>> = Vec::new();
        let mut idx = 0usize;
        while idx < level.len() {
            if idx + 1 < level.len() {
                let t = Instant::now();
                let j = join(&level[idx], &level[idx + 1]).expect("join");
                println!(
                    "join r{round} ({idx},{}) : {} ms | receipt {} B | VmHWM {} KB",
                    idx + 1,
                    t.elapsed().as_millis(),
                    bincode::serialize(&j).expect("ser").len(),
                    vm_hwm_kb()
                );
                next.push(j);
                idx += 2;
            } else {
                next.push(level[idx].clone());
                idx += 1;
            }
        }
        level = next;
        round += 1;
    }
    let rec_ms = t_all.elapsed().as_millis();

    let final_rct = level.pop().expect("final receipt");
    let ser = bincode::serialize(&final_rct).expect("ser final");
    let t = Instant::now();
    // 残段 span 没有真实 journal 字节 → 用 seal 级完整性校验（recursion STARK 验证）。
    // 全量运行时以 Receipt::new(inner, journal).verify(image_id) 做全覆盖校验。
    let _ = image_id;
    final_rct
        .verify_integrity()
        .expect("verify final succinct (seal)");
    let verify_us = t.elapsed().as_micros();

    std::fs::create_dir_all("out").ok();
    std::fs::write(
        format!("out/receipt-succinct-smoke-v2-po2{}.bin", po2),
        &ser,
    )
    .unwrap();
    let hwm = vm_hwm_kb();
    println!(
        "FINAL: recursion total {rec_ms} ms | receipt {} B | verify {verify_us} us | VmHWM {hwm} KB",
        ser.len()
    );
    std::fs::write(
        format!("out/smoke-v2-po2{}-n{}.txt", po2, nseg),
        format!(
            "po2={po2}\nn_segments={nseg}\nrecursion_total_ms={rec_ms}\nfinal_receipt_bytes={}\nfinal_verify_us={verify_us}\nvm_hwm_kb={hwm}\n",
            ser.len()
        ),
    )
    .unwrap();
    println!("=== smoke-v2 done ===");
}
