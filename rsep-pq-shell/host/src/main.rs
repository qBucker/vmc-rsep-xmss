//! PQ 外壳实测 host：RSEP `C_RSEP` 语句在 RISC Zero STARK 下的
//! 证明/验证/尺寸基准。
//!
//! guest 与电路同一语句、同一 Poseidon 实例（派生域
//! `rsep-xmss-a2-stats`，即论文附录 B 统计核销实例）。
//! guest 源文件经 `#[path]` 与 guest crate 共享同一份代码。

use std::time::Instant;

extern crate alloc;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};

#[path = "../../guest/src/poseidon.rs"]
mod poseidon;
#[path = "../../guest/src/state.rs"]
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

/// 全层 Merkle 树，`layers[0]` 为叶子层。
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

fn main() {
    // ---- 1. 见证构造：h=10 状态树，叶子 3 执行 Fresh → Used ----
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

    let v_old = Fr::from(0u64); // Fresh
    let v_new = Fr::from(1u64); // Used
    leaves[LEAF_INDEX as usize] = v_new;
    let (rho_new, _) = build_tree(&params, &leaves);
    let c_new = C_OLD + 1;

    // host 侧先自检（与 guest 同一逻辑）
    assert_eq!(merkle_root(&params, v_old, LEAF_INDEX, &path), rho_old);
    assert_eq!(merkle_root(&params, v_new, LEAF_INDEX, &path), rho_new);

    // ---- 2. 编码 guest 输入 ----
    let mut words: Vec<u32> = vec![
        H as u32,
        0, // finalize = false
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

    // ---- 3. 加载 ELF 与 image id ----
    let elf_path = std::env::args().nth(1).unwrap_or_else(|| {
        "rsep-guest.elf".into()
    });
    let user_elf = std::fs::read(&elf_path).expect("read guest elf");
    // RISC Zero 3.x：execute/prove 消费的是 ProgramBinary 打包 blob
    // （header + user_elf + kernel_elf），kernel 用内置 V1Compat 默认核。
    let binary =
        risc0_binfmt::ProgramBinary::new(&user_elf, risc0_zkos_v1compat::V1COMPAT_ELF);
    let image_id = binary.compute_image_id().expect("image id");
    let elf = binary.encode();
    println!(
        "guest elf: {} bytes (user) -> {} bytes (program binary)",
        user_elf.len(),
        elf.len()
    );
    println!("image_id:  {}", image_id);

    // 中转产物：供 segprove 断点续传器复用（免重复打包/输入构造）
    std::fs::create_dir_all("out").ok();
    std::fs::write("out/program.bin", &elf).unwrap();
    std::fs::write(
        "out/input.bin",
        words
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<u8>>(),
    )
    .unwrap();

    let make_env = || {
        // 沙盒 4GB 硬顶：默认 po2=20（1M cycles/segment）单 segment trace
        // 即超内存（OOM 实测 x2）；po2=18 使单 segment 峰值 ~1/4。
        // segment 分块不改变 guest 语义与 image_id。
        ExecutorEnv::builder()
            .write_slice(&words)
            .segment_limit_po2(18)
            .build()
            .expect("env")
    };

    // ---- 4. 执行（cycle 计数）----
    // stage 参数（argv[2]）：exec | comp | succ | all（默认 all）。
    // 窗口生态适配：每个阶段结束立即独立落盘，prove 中途死亡不丢已完成阶段。
    let stage = std::env::args().nth(2).unwrap_or_else(|| "all".into());
    let t = Instant::now();
    let info = default_executor()
        .execute(make_env(), &elf)
        .expect("execute");
    let exec_ms = t.elapsed().as_millis();
    let cycles = info.cycles();
    let segments = info.segments.len();
    println!(
        "execute: {} ms | total cycles = {} | segments = {}",
        exec_ms, cycles, segments
    );
    std::fs::create_dir_all("out").ok();
    std::fs::write(
        "out/exec.txt",
        format!("execute_ms={}\ncycles={}\nsegments={}\n", exec_ms, cycles, segments),
    )
    .unwrap();
    drop(info);

    // journal 期望值（供各阶段 verify 后核对）
    let mut expect = Vec::new();
    expect.extend_from_slice(&words_from_fr(&rho_old));
    expect.extend_from_slice(&words_from_fr(&rho_new));
    expect.extend_from_slice(&[
        LEAF_INDEX as u32,
        (LEAF_INDEX >> 32) as u32,
        C_OLD as u32,
        (C_OLD >> 32) as u32,
        c_new as u32,
        (c_new >> 32) as u32,
    ]);
    let mut expect_bytes = Vec::with_capacity(expect.len() * 4);
    for w in &expect {
        expect_bytes.extend_from_slice(&w.to_le_bytes());
    }

    if stage == "exec" {
        return;
    }

    let prover = default_prover();

    // ---- 5. composite 证明（无递归，PQ STARK）----
    if stage == "all" || stage == "comp" {
        let t = Instant::now();
        let pi_comp = prover.prove(make_env(), &elf).expect("prove composite");
        let comp_ms = t.elapsed().as_millis();
        let comp_ser = bincode::serialize(&pi_comp.receipt).expect("ser");
        let comp_bytes = comp_ser.len();
        std::fs::write("out/receipt-composite.bin", &comp_ser).unwrap();
        let t = Instant::now();
        pi_comp.receipt.verify(image_id).expect("verify composite");
        let vcomp_us = t.elapsed().as_micros();
        let jok = pi_comp.receipt.journal.bytes == expect_bytes;
        println!(
            "composite: prove {} ms | verify {} us | receipt {} B | journal_ok {}",
            comp_ms, vcomp_us, comp_bytes, jok
        );
        std::fs::write(
            "out/comp.txt",
            format!(
                "prove_ms={}\nverify_us={}\nreceipt_bytes={}\njournal_ok={}\n",
                comp_ms, vcomp_us, comp_bytes, jok
            ),
        )
        .unwrap();
    }

    // ---- 6. succinct 证明（递归压缩，PQ STARK）----
    if stage == "all" || stage == "succ" {
        let t = Instant::now();
        let pi_succ = prover
            .prove_with_opts(make_env(), &elf, &ProverOpts::succinct())
            .expect("prove succinct");
        let succ_ms = t.elapsed().as_millis();
        let succ_ser = bincode::serialize(&pi_succ.receipt).expect("ser");
        let succ_bytes = succ_ser.len();
        std::fs::write("out/receipt-succinct.bin", &succ_ser).unwrap();
        let t = Instant::now();
        pi_succ.receipt.verify(image_id).expect("verify succinct");
        let vsucc_us = t.elapsed().as_micros();
        let jok = pi_succ.receipt.journal.bytes == expect_bytes;
        println!(
            "succinct:  prove {} ms | verify {} us | receipt {} B | journal_ok {}",
            succ_ms, vsucc_us, succ_bytes, jok
        );
        std::fs::write(
            "out/succ.txt",
            format!(
                "prove_ms={}\nverify_us={}\nreceipt_bytes={}\njournal_ok={}\n",
                succ_ms, vsucc_us, succ_bytes, jok
            ),
        )
        .unwrap();
    }

    println!(
        "=== done stage={} | cycles: {} | segments: {} ===",
        stage, cycles, segments
    );
}
