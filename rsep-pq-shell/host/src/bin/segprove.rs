//! 断点续传 prover：窗口生态适配。
//!
//! main.rs 一把梭 prove 需 30-60 分钟连续窗口（沙盒窗口 4-7 分钟，必死）。
//! 本工具把 composite prove 拆成 242 个独立 segment prove（po2=18），
//! 每段完成立即落盘 + 拷 /mnt 银行；窗口死亡后重跑自动跳过已完成段。
//!
//! 用法：
//!   segprove <program.bin> segprove [seg_dir] [bank_dir]
//!   segprove <program.bin> assemble [seg_dir] [out_dir]
//!
//! 输入：main.rs exec 阶段写出的 out/program.bin（ProgramBinary blob）
//!       与 out/input.bin（u32 LE words）。
//!
//! 数字口径：prove_total_ms = Σ 各段 prove 墙钟（不含 execute/IO），
//! 比一把梭更能反映纯证明时间。

use std::path::Path;
use std::time::Instant;

use risc0_zkvm::{
    get_prover_server, ExecutorEnv, ExecutorImpl, InnerReceipt, MaybePruned, Output, ProverOpts,
    Receipt, SegmentReceipt, VerifierContext,
};
use risc0_zkvm::sha::Digestible;

fn read_words(path: &str) -> Vec<u32> {
    let bytes = std::fs::read(path).expect("read input.bin");
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

fn bank_copy(src: &str, bank_dir: &str) {
    // portal 写突发会断连 1-3 分钟；小文件重试 5 次 x 10s
    let name = Path::new(src).file_name().unwrap();
    let dst = format!("{}/{}", bank_dir, name.to_string_lossy());
    for attempt in 0..5 {
        match std::fs::copy(src, &dst) {
            Ok(_) => return,
            Err(e) => {
                eprintln!("bank copy attempt {} failed: {}", attempt, e);
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        }
    }
    eprintln!("WARN: bank copy gave up on {}", src);
}

fn main() {
    let blob_path = std::env::args().nth(1).expect("program.bin path");
    let mode = std::env::args().nth(2).unwrap_or_else(|| "segprove".into());
    let seg_dir = std::env::args().nth(3).unwrap_or_else(|| "segs".into());
    let aux_dir = std::env::args().nth(4).unwrap_or_else(|| {
        if mode == "assemble" {
            "out".into()
        } else {
            "/mnt/agents/cache/receipts".into()
        }
    });

    let blob = std::fs::read(&blob_path).expect("read program.bin");
    let image_id = risc0_binfmt::compute_image_id(&blob).expect("image id");
    println!("image_id: {}", image_id);

    let dir = Path::new(&blob_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let words = read_words(&format!("{}/input.bin", dir.display()));

    let env = ExecutorEnv::builder()
        .write_slice(&words)
        .segment_limit_po2(18)
        .build()
        .expect("env");

    // server 侧执行（client 的 default_executor 只回 SessionInfo 摘要）
    let t = Instant::now();
    let session = ExecutorImpl::from_elf(env, &blob)
        .expect("executor")
        .run()
        .expect("execute");
    println!(
        "execute: {} ms | {} segments",
        t.elapsed().as_millis(),
        session.segments.len()
    );

    let ctx = VerifierContext::default();
    let server = get_prover_server(&ProverOpts::default()).expect("prover server");

    if mode == "segprove" {
        std::fs::create_dir_all(&seg_dir).ok();
        std::fs::create_dir_all(&aux_dir).ok();
        let n = session.segments.len();
        let timing_path = format!("{}/timing.txt", seg_dir);
        for (i, seg_ref) in session.segments.iter().enumerate() {
            let rct_path = format!("{}/seg-{:03}.rct", seg_dir, i);
            if Path::new(&rct_path).exists() {
                continue;
            }
            let seg = seg_ref.resolve().expect("resolve segment");
            let t = Instant::now();
            let rct = server.prove_segment(&ctx, &seg).expect("prove segment");
            let ms = t.elapsed().as_millis();
            let bytes = bincode::serialize(&rct).expect("ser receipt");
            let tmp = format!("{}.tmp", rct_path);
            std::fs::write(&tmp, &bytes).unwrap();
            std::fs::rename(&tmp, &rct_path).unwrap();
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&timing_path)
                .unwrap();
            writeln!(f, "{} {}", i, ms).unwrap();
            drop(f);
            bank_copy(&rct_path, &aux_dir);
            bank_copy(&timing_path, &aux_dir);
            println!(
                "[{}/{}] seg {} proved: {} ms, {} B",
                i + 1,
                n,
                i,
                ms,
                bytes.len()
            );
        }
        println!("segprove pass complete");
        return;
    }

    if mode == "verify1" {
        // 单段 verify 实测：composite verify 时间 ≈ 段数 x 单段（投影口径锚点）
        let rct_path = format!("{}/seg-000.rct", seg_dir);
        let bytes = std::fs::read(&rct_path).expect("read seg-000.rct");
        let rct: SegmentReceipt = bincode::deserialize(&bytes).expect("deser");
        // 预热一次（排除 lazy 初始化），再测 3 次取最小
        rct.verify_integrity_with_context(&ctx).expect("warmup verify");
        let mut best = u128::MAX;
        for _ in 0..3 {
            let t = Instant::now();
            rct.verify_integrity_with_context(&ctx).expect("verify segment");
            best = best.min(t.elapsed().as_micros());
        }
        println!(
            "segment verify_integrity: {} us (best of 3) | receipt {} B",
            best,
            bytes.len()
        );
        std::fs::write(
            format!("{}/seg-verify.txt", seg_dir),
            format!("verify_us={}\nreceipt_bytes={}\n", best, bytes.len()),
        )
        .unwrap();
        return;
    }

    if mode == "assemble" {
        let n = session.segments.len();
        let mut segments: Vec<SegmentReceipt> = Vec::with_capacity(n);
        for i in 0..n {
            let rct_path = format!("{}/seg-{:03}.rct", seg_dir, i);
            let bytes = std::fs::read(&rct_path)
                .unwrap_or_else(|e| panic!("missing {}: {}", rct_path, e));
            segments.push(bincode::deserialize(&bytes).expect("deser receipt"));
        }

        // 与 prove_session 一致：journal 并入最后一段 claim。
        // （Merge trait 是 pub(crate)，此处直接构造等价结构赋值；
        //  seal 证明对象在 prove 时已固定，claim 字段仅作链式/输出核对，
        //  与 prove_session 的 merge 路径产出逐字节一致即可通过 verify。）
        let journal_bytes = session
            .journal
            .as_ref()
            .map(|j| j.bytes.clone())
            .unwrap_or_default();
        let assumptions: Vec<risc0_zkvm::Assumption> = session
            .assumptions
            .iter()
            .map(|(a, _)| a.clone())
            .collect();
        let output = Output {
            journal: MaybePruned::Pruned(session.journal.as_ref().expect("journal").digest()),
            assumptions: MaybePruned::Value(risc0_zkvm::Assumptions::from(assumptions)),
        };
        segments
            .last_mut()
            .expect("non-empty")
            .claim
            .output = MaybePruned::Value(Some(output));

        // CompositeReceipt 是 #[non_exhaustive]（protos 转换模块私有），
        // 无法字面量构造。骨架法：以 session_limit 截断的 1-2 段迷你 session
        // 走官方 prove_session 得真 CompositeReceipt 实例（~10s），
        // 再整体替换其 segments 字段为我们的 242 段真实 receipts。
        let env_skel = ExecutorEnv::builder()
            .write_slice(&words)
            .segment_limit_po2(18)
            .session_limit(Some(300_000))
            .build()
            .expect("skel env");
        let skel_session = ExecutorImpl::from_elf(env_skel, &blob)
            .expect("skel executor")
            .run()
            .expect("skel execute");
        println!("skeleton session: {} segments", skel_session.segments.len());
        let skel_info = server
            .prove_session(&ctx, &skel_session)
            .expect("skeleton prove_session");
        let mut skeleton = match skel_info.receipt.inner {
            InnerReceipt::Composite(c) => c,
            _ => panic!("skeleton receipt is not composite"),
        };
        skeleton.segments = segments;
        let receipt = Receipt::new(InnerReceipt::Composite(skeleton), journal_bytes);

        let t = Instant::now();
        receipt.verify(image_id).expect("verify composite");
        let verify_us = t.elapsed().as_micros();

        let ser = bincode::serialize(&receipt).expect("ser");
        std::fs::create_dir_all(&aux_dir).ok();
        std::fs::write(format!("{}/receipt-composite.bin", aux_dir), &ser).unwrap();

        // 纯 prove 总时长 = 各段墙钟之和
        let timing_path = format!("{}/timing.txt", seg_dir);
        let total_ms: u128 = std::fs::read_to_string(&timing_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1))
            .filter_map(|s| s.parse::<u128>().ok())
            .sum();

        println!("=== composite (resumable) ===");
        println!(
            "prove_total {} ms | verify {} us | receipt {} B | segments {}",
            total_ms,
            verify_us,
            ser.len(),
            n
        );
        std::fs::write(
            format!("{}/comp.txt", aux_dir),
            format!(
                "prove_total_ms={}\nverify_us={}\nreceipt_bytes={}\nsegments={}\n",
                total_ms,
                verify_us,
                ser.len(),
                n
            ),
        )
        .unwrap();
        return;
    }

    eprintln!("unknown mode: {}", mode);
    std::process::exit(2);
}
