//! E1 基准：SLH-DSA（SPHINCS+ SHA2，PQClean clean 参考实现）四档对照。
//!
//! 用法：
//! ```text
//! cargo run --release --example slhdsa_bench -- [variant] [keygen_n] [sign_n] [verify_n]
//! ```
//! `variant ∈ {all, 128s, 128f, 192s, 192f}`（默认 all）；默认 n = 10 / 1000 / 1000。
//!
//! ## 用途
//!
//! 为论文 Table 2（SLH-DSA 对照行）提供同机实测：keygen / sign（detached）/
//! verify（detached）耗时与尺寸，与 XMSS 核心、RSEP-XMSS 并排。
//!
//! ## 口径
//!
//! * 实现：`pqcrypto-sphincsplus 0.7.2`（PQClean **clean** 版；未启用 AVX2 feature）。
//! * 每相位 1 次不计时预热；报告 min/q1/med/q3/max（q1/q3 取最近秩）。
//! * verify 为单一签名重复验证 n 次；消息固定 `0x77*32`（与 measure.rs 同口径）。
//! * 单线程。

use std::time::{Duration, Instant};

use pqcrypto_sphincsplus::{
    sphincssha2128fsimple, sphincssha2128ssimple, sphincssha2192fsimple, sphincssha2192ssimple,
};

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

/// n 次采样的 min / q1 / median / q3 / max 摘要（q1/q3 最近秩）。
fn summary(xs: &[f64]) -> String {
    let mut v: Vec<f64> = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    let idx = |p: f64| (((n - 1) as f64) * p).round() as usize;
    format!(
        "min={:.3} q1={:.3} med={:.3} q3={:.3} max={:.3} (n={})",
        v[0],
        v[idx(0.25)],
        v[idx(0.5)],
        v[idx(0.75)],
        v[n - 1],
        n
    )
}

fn vm_hwm_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|r| r.trim().trim_end_matches("kB").trim().parse().ok())
}

macro_rules! bench_variant {
    ($label:expr, $m:ident, $msg:expr, $keygen_n:expr, $sign_n:expr, $verify_n:expr) => {{
        let t_var = Instant::now();
        println!("variant: {}", $label);
        println!("public_key_bytes: {}", $m::public_key_bytes());
        println!("secret_key_bytes: {}", $m::secret_key_bytes());
        println!("signature_bytes: {}", $m::signature_bytes());

        // ---- keygen ----
        let _ = $m::keypair(); // warmup（不计时）
        let mut kg: Vec<f64> = Vec::with_capacity($keygen_n);
        let mut last = None;
        for _ in 0..$keygen_n {
            let t = Instant::now();
            let kp = $m::keypair();
            kg.push(ms(t.elapsed()));
            last = Some(kp);
        }
        let (pk, sk) = last.expect("keygen_n > 0");
        println!("keygen_ms: {}", summary(&kg));

        // ---- sign（detached） ----
        let _ = $m::detached_sign($msg, &sk); // warmup（不计时）
        let mut sg: Vec<f64> = Vec::with_capacity($sign_n);
        let mut sig_last = None;
        for _ in 0..$sign_n {
            let t = Instant::now();
            let s = $m::detached_sign($msg, &sk);
            sg.push(ms(t.elapsed()));
            sig_last = Some(s);
        }
        let sig_last = sig_last.expect("sign_n > 0");
        println!("sign_ms: {}", summary(&sg));

        // ---- verify（detached，单一签名重复验证） ----
        assert!($m::verify_detached_signature(&sig_last, $msg, &pk).is_ok());
        let _ = $m::verify_detached_signature(&sig_last, $msg, &pk); // warmup（不计时）
        let mut vf: Vec<f64> = Vec::with_capacity($verify_n);
        let mut ok = 0usize;
        for _ in 0..$verify_n {
            let t = Instant::now();
            if $m::verify_detached_signature(&sig_last, $msg, &pk).is_ok() {
                ok += 1;
            }
            vf.push(ms(t.elapsed()));
        }
        assert_eq!(ok, $verify_n, "verify must succeed on every repetition");
        println!("verify_ms: {}", summary(&vf));

        if let Some(kib) = vm_hwm_kib() {
            println!("vmhwm_kib: {}", kib);
        }
        println!("variant_wall_ms: {:.1}", ms(t_var.elapsed()));
    }};
}

fn usage() -> ! {
    eprintln!(
        "usage: slhdsa_bench [all|128s|128f|192s|192f] [keygen_n] [sign_n] [verify_n]\n\
         (defaults: all 10 1000 1000)"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let which = args.first().map(|s| s.as_str()).unwrap_or("all");
    let keygen_n: usize = args.get(1).map(|s| s.parse().expect("keygen_n")).unwrap_or(10);
    let sign_n: usize = args.get(2).map(|s| s.parse().expect("sign_n")).unwrap_or(1000);
    let verify_n: usize = args.get(3).map(|s| s.parse().expect("verify_n")).unwrap_or(1000);

    println!(
        "# slhdsa bench (E1): pqcrypto-sphincsplus 0.7.2 (PQClean clean, AVX2 feature off)"
    );
    println!("# msg=0x77*32; keygen_n={keygen_n}, sign_n={sign_n}, verify_n={verify_n}; single-threaded; 1 warmup per phase");

    let msg = [0x77u8; 32];

    let run = |v: &str| match v {
        "128s" => bench_variant!(
            "SLH-DSA-SHA2-128s (sphincs-sha2-128s-simple)",
            sphincssha2128ssimple,
            &msg,
            keygen_n,
            sign_n,
            verify_n
        ),
        "128f" => bench_variant!(
            "SLH-DSA-SHA2-128f (sphincs-sha2-128f-simple)",
            sphincssha2128fsimple,
            &msg,
            keygen_n,
            sign_n,
            verify_n
        ),
        "192s" => bench_variant!(
            "SLH-DSA-SHA2-192s (sphincs-sha2-192s-simple)",
            sphincssha2192ssimple,
            &msg,
            keygen_n,
            sign_n,
            verify_n
        ),
        "192f" => bench_variant!(
            "SLH-DSA-SHA2-192f (sphincs-sha2-192f-simple)",
            sphincssha2192fsimple,
            &msg,
            keygen_n,
            sign_n,
            verify_n
        ),
        _ => usage(),
    };

    match which {
        "all" => {
            for v in ["128s", "128f", "192s", "192f"] {
                run(v);
            }
        }
        "128s" | "128f" | "192s" | "192f" => run(which),
        _ => usage(),
    }

    println!("all_done");
}
