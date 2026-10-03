//! baseline 探测：同会话的 plain XMSS vs RSEP-XMSS（h 可配）。
//!
//! 用法：
//! ```text
//! cargo run --release --example baseline -- <h> [iters]
//! ```
//! 例：`cargo run --release --example baseline -- 10 5`
//!
//! ## 用途
//!
//! 为论文 "accountability overhead" 表提供同栈 A/B 实测：
//! * plain XMSS 核心（`XmssSecret::sign` / `xmss_verify`——无证明、无状态机）
//! * RSEP-XMSS（同会话真实流程；与 `measure.rs` 口径一致）
//! * Poseidon hash2 微基准（per-event append 成本 = 2 次 hash2 的脚注）
//!
//! ## 输出约定
//!
//! 与 `measure.rs` 相同：每行 `键: 值`；`#` 开头为注释；
//! 时间单位 ms，尺寸单位 B。

use std::time::{Duration, Instant};

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsep_xmss::poseidon::PoseidonParams;
use rsep_xmss::proof;
use rsep_xmss::rsep::{self, Verdict, VerifierState};
use rsep_xmss::wots::WOTS_N;
use rsep_xmss::xmss::{self, XmssSignature};
use rsep_xmss::Fr;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

/// n 次采样的 min / median / max 摘要。
fn summary(xs: &[f64]) -> String {
    let mut v: Vec<f64> = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = v[v.len() / 2];
    format!(
        "min={:.3} med={:.3} max={:.3} (n={})",
        v[0], med, v[v.len() - 1], v.len()
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let h: u8 = args.first().map(|s| s.parse().expect("h")).unwrap_or(10);
    let iters: usize = args
        .get(1)
        .map(|s| s.parse().expect("iters"))
        .unwrap_or(5)
        .max(1)
        .min(1usize << h);
    let run_start = Instant::now();

    let p = PoseidonParams::derive(b"measure");
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EED_1234);
    let msg = [0x77u8; WOTS_N];

    println!("# baseline probe: plain XMSS core vs RSEP-XMSS (same session)");
    println!("# rsep-xmss baseline: h={h}, iters={iters}, msg=0x77*32");
    println!("# prof=release; poseidon-domain=b\"measure\"");

    // ---- 1. Poseidon hash2 微基准（链式，模拟 append 的数据依赖） ----
    let reps = 1000usize;
    let mut hash_times = Vec::with_capacity(reps);
    let mut acc = Fr::from(0u64);
    for i in 0..reps {
        let t = Instant::now();
        acc = p.hash2(acc, Fr::from(i as u64 + 1));
        hash_times.push(ms(t.elapsed()));
    }
    std::hint::black_box(acc);
    println!("hash2_ms: {}", summary(&hash_times));

    // ---- 2. keygen（一次；plain 与 RSEP 共用同一棵树） ----
    let t = Instant::now();
    let (public, mut secret) = rsep::keygen(&p, h, &mut rng).unwrap();
    println!("keygen_ms: {:.3}", ms(t.elapsed()));

    // ---- 3. plain XMSS：sign / verify（探测高位叶子，不触碰 RSEP 状态） ----
    let mut xmss_sigs: Vec<XmssSignature> = Vec::with_capacity(iters);
    let mut xmss_sign_ms = Vec::with_capacity(iters);
    for i in 0..iters as u64 {
        let idx = (1u64 << h) - 1 - i;
        let t = Instant::now();
        let sig = secret.xmss.sign(&p, idx, &msg);
        xmss_sign_ms.push(ms(t.elapsed()));
        xmss_sigs.push(sig);
    }
    println!("xmss_sign_ms: {}", summary(&xmss_sign_ms));

    let mut xmss_verify_ms = Vec::with_capacity(iters);
    for sig in &xmss_sigs {
        let t = Instant::now();
        let ok = xmss::xmss_verify(&p, &public.xmss_pub, &msg, sig);
        xmss_verify_ms.push(ms(t.elapsed()));
        assert!(ok, "plain XMSS signature must verify");
    }
    println!("xmss_verify_ms: {}", summary(&xmss_verify_ms));

    // ---- 4. RSEP-XMSS：sign / Groth16-verify / e2e verify（同会话对照） ----
    let mut v = VerifierState::init(&public);
    let mut rsep_sign_ms = Vec::new();
    let mut groth16_verify_ms = Vec::new();
    let mut rsep_verify_ms = Vec::new();
    let mut sig0 = None;
    for i in 0..iters as u64 {
        let t = Instant::now();
        let sig = rsep::sign(&public, &mut secret, &msg, i, &mut rng).unwrap();
        rsep_sign_ms.push(ms(t.elapsed()));

        // 纯 Groth16 verify：公开输入与验证器"当前"状态一致（真证明）
        let inputs = [
            v.cur_root,
            sig.new_root,
            Fr::from(sig.leaf_index),
            Fr::from(v.last_counter),
            Fr::from(sig.new_counter),
        ];
        let t = Instant::now();
        let ok = proof::verify(&public.sign_pvk, &sig.proof, &inputs).unwrap();
        groth16_verify_ms.push(ms(t.elapsed()));
        assert!(ok, "real proof must verify");

        // 端到端 verify（XMSS 检查 + 计数器 + Groth16 + 状态更新）
        let t = Instant::now();
        match v.verify_signature(&public, &msg, &sig).unwrap() {
            Verdict::Accept => {}
            other => panic!("expected Accept, got {other:?}"),
        }
        rsep_verify_ms.push(ms(t.elapsed()));
        if i == 0 {
            sig0 = Some(sig);
        }
    }
    println!("rsep_sign_ms: {}", summary(&rsep_sign_ms));
    println!("rsep_groth16_verify_ms: {}", summary(&groth16_verify_ms));
    println!("rsep_verify_ms: {}", summary(&rsep_verify_ms));

    // ---- 5. 尺寸 ----
    let sig0 = sig0.unwrap();
    let xs = sig0.xmss_sig.as_ref().unwrap();
    let xmss_sig_bytes = xs.wots_sig.len() * 32 + xs.auth_path.len() * 32 + 8;
    let pi_bytes = proof::proof_to_bytes(&sig0.proof).unwrap().len();
    let vk_bytes = proof::vk_to_bytes(&public.sign_vk).unwrap().len();
    let rsep_extra = pi_bytes + 8 + 32; // pi + c + root'
    println!("xmss_sig_bytes: {xmss_sig_bytes}");
    println!("pi_bytes: {pi_bytes}");
    println!("vk_bytes: {vk_bytes}");
    println!("rsep_sig_extra_bytes: {rsep_extra}  # pi + c + root'");
    println!("rsep_sig_total_bytes: {}", xmss_sig_bytes + rsep_extra);

    println!("wall_total_ms: {:.3}", ms(run_start.elapsed()));
}
