//! 测量工具：RSEP-XMSS 端到端与 Groth16 组件计时（h 可配）。
//!
//! 用法：
//! ```text
//! cargo run --release --example measure -- <h> [iters] [msg_byte]
//! ```
//! 例：`cargo run --release --example measure -- 10 5`
//! 默认消息字节 `0x77`（w=16 数字 (7,7)，接近平均链长）；
//! 传 `0x42` 可复现早期口径（该消息数字偏小，sign 偏快、verify 偏慢）。
//!
//! ## 输出约定
//!
//! 每行 `键: 值`；`#` 开头为注释；时间单位 ms、大小单位 B / KiB。
//!
//! ## 测量语义
//!
//! * `*_iso_*`：独立 Groth16 组件计时，n=5 次，使用占位 witness
//!   （仅计时，不满足约束、非有效命题）；证明时间只取决于电路
//!   结构而非 witness 取值，故该计时有效。
//! * 其余为真实流程（keygen / sign / verify / finalize）端到端计时。
//! * `vmhwm_*`：进程峰值常驻内存（Linux `/proc/self/status`）。

use std::time::{Duration, Instant};

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsep_xmss::circuit::{PoseidonConfig, RsepCircuit};
use rsep_xmss::poseidon::PoseidonParams;
use rsep_xmss::proof;
use rsep_xmss::rsep::{self, Verdict, VerifierState};
use rsep_xmss::wots::WOTS_N;
use rsep_xmss::{Fr, LeafState};

fn vm_hwm_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|r| r.trim().trim_end_matches("kB").trim().parse().ok())
}

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

/// 构造一个电路模板（占位 witness；仅用于 setup / 独立 prove 计时）。
fn template(h: usize, cfg: &PoseidonConfig, finalize: bool) -> RsepCircuit {
    RsepCircuit {
        poseidon: cfg.clone(),
        h,
        finalize,
        rho_old: Fr::from(0u64),
        rho_new: Fr::from(0u64),
        leaf_index: 0,
        c_old: 0,
        c_new: 1,
        auth_path: vec![Fr::from(0u64); h],
        v_old: if finalize {
            LeafState::Used.to_fr()
        } else {
            LeafState::Fresh.to_fr()
        },
        v_new: if finalize {
            LeafState::Spent.to_fr()
        } else {
            LeafState::Used.to_fr()
        },
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let h: u8 = args.first().map(|s| s.parse().expect("h")).unwrap_or(10);
    let iters: usize = args
        .get(1)
        .map(|s| s.parse().expect("iters"))
        .unwrap_or(3)
        .max(1)
        .min(1usize << h);
    let msg_byte: u8 = args
        .get(2)
        .map(|s| s.parse().expect("msg_byte"))
        .unwrap_or(0x77);
    let run_start = Instant::now();

    let p = PoseidonParams::derive(b"measure");
    let cfg: PoseidonConfig = (&p).into();
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EED_1234);
    let msg = [msg_byte; WOTS_N];
    let iso_reps = 5usize;

    println!("# rsep-xmss measure: h={h}, iters={iters}, msg=0x{msg_byte:02x}*32");
    println!("# prof=release; poseidon-domain=b\"measure\"; iso_reps={iso_reps}");

    // ---- 1. 独立 Groth16 setup / prove / verify（n=iso_reps，占位 witness 仅计时） ----
    let mut setup_times = Vec::with_capacity(iso_reps);
    let mut pk_iso = None;
    let mut vk_iso = None;
    for _ in 0..iso_reps {
        let t = Instant::now();
        let (pk, vk) = proof::setup(template(h as usize, &cfg, false), &mut rng).unwrap();
        setup_times.push(ms(t.elapsed()));
        pk_iso = Some(pk);
        vk_iso = Some(vk);
    }
    let pk_iso = pk_iso.unwrap();
    let pvk_iso = proof::prepare(&vk_iso.unwrap());
    println!("setup_sign_iso_ms: {}", summary(&setup_times));

    let mut prove_times = Vec::with_capacity(iso_reps);
    let mut iso_proof = None;
    for _ in 0..iso_reps {
        let t = Instant::now();
        let pf = proof::prove(
            &pk_iso,
            template(h as usize, &cfg, false),
            &mut rng,
        )
        .unwrap();
        prove_times.push(ms(t.elapsed()));
        iso_proof = Some(pf);
    }
    let iso_proof = iso_proof.unwrap();
    println!("prove_sign_iso_ms: {}", summary(&prove_times));

    let iso_inputs = [
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(1u64),
    ];
    let mut verify_times = Vec::with_capacity(iso_reps);
    let mut iso_ok = true;
    for _ in 0..iso_reps {
        let t = Instant::now();
        iso_ok = proof::verify(&pvk_iso, &iso_proof, &iso_inputs).unwrap();
        verify_times.push(ms(t.elapsed()));
    }
    println!(
        "verify_sign_iso_ms: {}  # placeholder-satisfied={iso_ok}",
        summary(&verify_times)
    );

    // ---- 2. 真实 keygen（XMSS 树 + 状态树 + 两次 Groth16 setup） ----
    let t = Instant::now();
    let (public, mut secret) = rsep::keygen(&p, h, &mut rng).unwrap();
    println!("keygen_ms: {:.3}", ms(t.elapsed()));
    if let Some(v) = vm_hwm_kib() {
        println!("vmhwm_after_keygen_kib: {v}");
    }

    // ---- 3. 纯 XMSS 签名计时（探测叶子，纯函数不消耗状态） ----
    let probe = (1u64 << h) - 1;
    let t = Instant::now();
    let _ = secret.xmss.sign(&p, probe, &msg);
    println!("xmss_sign_only_ms: {:.3}", ms(t.elapsed()));

    // ---- 4. 端到端 sign / verify 循环 ----
    let mut v = VerifierState::init(&public);
    let mut sign_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut groth16_verify_ms = Vec::new();
    let mut proof_bytes = 0usize;
    let mut xmss_sig_bytes = 0usize;

    for i in 0..iters as u64 {
        let t = Instant::now();
        let sig = rsep::sign(&public, &mut secret, &msg, i, &mut rng).unwrap();
        sign_ms.push(ms(t.elapsed()));

        if i == 0 {
            proof_bytes = proof::proof_to_bytes(&sig.proof).unwrap().len();
            let xs = sig.xmss_sig.as_ref().unwrap();
            xmss_sig_bytes = xs.wots_sig.len() * 32 + xs.auth_path.len() * 32 + 8;
        }

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
        verify_ms.push(ms(t.elapsed()));
    }

    // ---- 5. finalize（USED → SPENT；leaf 0 已在第 0 轮签名） ----
    let t = Instant::now();
    let fin = rsep::finalize(&public, &mut secret, 0, &mut rng).unwrap();
    println!("finalize_prove_ms: {:.3}", ms(t.elapsed()));
    let t = Instant::now();
    match v.verify_finalization(&public, &fin).unwrap() {
        Verdict::Accept => {}
        other => panic!("expected Accept, got {other:?}"),
    }
    println!("finalize_verify_ms: {:.3}", ms(t.elapsed()));

    // ---- 6. 尺寸 ----
    let vk_bytes = proof::vk_to_bytes(&public.sign_vk).unwrap().len();
    let fin_proof_bytes = proof::proof_to_bytes(&fin.proof).unwrap().len();
    let rsep_extra = proof_bytes + 8 + 32;
    println!("proof_bytes: {proof_bytes}");
    println!("fin_proof_bytes: {fin_proof_bytes}");
    println!("vk_bytes: {vk_bytes}");
    println!("xmss_sig_bytes: {xmss_sig_bytes}");
    println!("rsep_sig_extra_bytes: {rsep_extra}  # pi + c + root'");
    println!("rsep_sig_total_bytes: {}", xmss_sig_bytes + rsep_extra);

    // ---- 7. 汇总 ----
    for (name, xs) in [
        ("sign_ms", &sign_ms),
        ("verify_e2e_ms", &verify_ms),
        ("groth16_verify_ms", &groth16_verify_ms),
    ] {
        let list: Vec<String> = xs.iter().map(|x| format!("{x:.3}")).collect();
        println!("{name}: {} [{}]", summary(xs), list.join(", "));
    }
    if let Some(v) = vm_hwm_kib() {
        println!("vmhwm_final_kib: {v}");
    }
    println!("wall_total_ms: {:.3}", ms(run_start.elapsed()));
}
