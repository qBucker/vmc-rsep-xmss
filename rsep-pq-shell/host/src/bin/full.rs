//! 全量递归复合驱动（论文批，O2 内核）：全 execute → 逐段 prove（checkpoint）→
//! lift ×N（checkpoint）→ join 树（checkpoint）→ final + `Receipt::new(inner, journal)`
//! `.verify(image_id)` 全覆盖校验。
//!
//! 用法: full [guest.elf] [segment_po2]        默认 ../rsep-guest.elf 19
//! 产出: out/full-v1/{meta.txt,timing.csv,seg-NNN.bin,lift-NNN.bin,join-rR-JJJ.bin,final.bin,report.txt}
//!
//! 断点续跑: seg/lift/join 三级 checkpoint 全部原子落盘（.tmp→rename）；
//! 重启后 execute 重跑（~2 s），已完成项从盘加载，只补缺项。
//! 同构守卫: meta.txt 记录 po2 / 段数 / image_id / journal 摘要——不匹配即拒跑（防混构建）。
//! 归档纪律: timing.csv 为逐项原始账（append + 逐行 flush），report.txt 为汇总；
//! 两者 + run-full.sh 日志头（环境披露）构成论文批 raw。

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

extern crate alloc;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use risc0_zkvm::{
    get_prover_server,
    recursion::{join, lift},
    DeserializeOwned, ExecutorEnv, ExecutorImpl, InnerReceipt, ProverOpts, Receipt, ReceiptClaim,
    SegmentReceipt, SuccinctReceipt, VerifierContext,
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
const OUT: &str = "out/full-v1";

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

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 原子落盘：先写 .tmp 再 rename（同目录、同 fs）。
fn save_atomic(path: &Path, bytes: &[u8]) {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).unwrap_or_else(|e| panic!("write {}: {e}", tmp.display()));
    fs::rename(&tmp, path).unwrap_or_else(|e| panic!("rename {}: {e}", path.display()));
}

fn load_bincode<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let data = fs::read(path).ok()?;
    if data.is_empty() {
        return None;
    }
    bincode::deserialize(&data).ok()
}

fn csv_line(csv: &mut File, phase: &str, idx: &str, ms: u128, bytes: usize, resumed: bool) {
    let _ = writeln!(
        csv,
        "{},{phase},{idx},{ms},{bytes},{},{}",
        now_ts(),
        vm_hwm_kb(),
        u8::from(resumed)
    );
    let _ = csv.flush();
}

fn blake2b_hex(data: &[u8]) -> String {
    use blake2::Digest as _;
    let mut h = blake2::Blake2b512::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn median(v: &[u128]) -> u128 {
    if v.is_empty() {
        return 0;
    }
    let mut s = v.to_vec();
    s.sort_unstable();
    s[s.len() / 2]
}

fn main() {
    let t_start = Instant::now();
    let args: Vec<String> = std::env::args().collect();
    let elf_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "../rsep-guest.elf".into());
    let po2: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(19);

    // ---- 见证构造（与 host/main.rs、smoke.rs 相同）----
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

    // host 侧期望 journal（22 words，与 guest commit_slice 同构）
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
    let expect_bytes: Vec<u8> = expect.iter().flat_map(|w| w.to_le_bytes()).collect();

    let user_elf = fs::read(&elf_path).expect("read guest elf");
    let binary = risc0_binfmt::ProgramBinary::new(&user_elf, risc0_zkos_v1compat::V1COMPAT_ELF);
    let image_id = binary.compute_image_id().expect("image id");
    let elf = binary.encode();
    println!("full-v1: elf={elf_path} | segment_po2={po2} | image_id={image_id}");

    fs::create_dir_all(OUT).expect("mkdir out");
    let mut csv = OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{OUT}/timing.csv"))
        .expect("open csv");
    let _ = writeln!(csv, "# session_start ts={} po2={po2} elf={elf_path}", now_ts());
    let _ = csv.flush();

    // ---- 1. 全量 execute ----
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
    let exec_ms = t.elapsed().as_millis();
    let n_seg = session.segments.len();
    let ucyc = session.user_cycles;
    let pcyc = session.paging_cycles;
    let rcyc = session.reserved_cycles;
    let tcyc = session.total_cycles;
    let journal_bytes: Vec<u8> = session
        .journal
        .as_ref()
        .map(|j| j.bytes.clone())
        .unwrap_or_default();
    println!(
        "execute: {exec_ms} ms | segments={n_seg} | user_cycles={ucyc} | total_cycles={tcyc} | VmHWM {} KB",
        vm_hwm_kb()
    );
    csv_line(&mut csv, "exec", "0", exec_ms, 0, false);

    // ---- meta 同构守卫（防混构建/混输入续跑）----
    let meta_path = Path::new(OUT).join("meta.txt");
    let meta_now = format!(
        "po2={po2}\nn_segments={n_seg}\nimage_id={image_id}\nelf_bytes={}\njournal_blake2b={}\n",
        user_elf.len(),
        blake2b_hex(&journal_bytes)
    );
    if meta_path.exists() {
        let prev = fs::read_to_string(&meta_path).unwrap_or_default();
        if prev != meta_now {
            eprintln!(
                "FATAL: meta mismatch — checkpoint dir belongs to a different build/input.\n--- prev ---\n{prev}--- now ---\n{meta_now}"
            );
            std::process::exit(2);
        }
    } else {
        fs::write(&meta_path, &meta_now).unwrap();
    }

    let ctx = VerifierContext::default();
    let server = get_prover_server(&ProverOpts::default()).expect("prover server");

    // ---- 2. 逐段 prove（checkpoint 落盘）----
    let mut n_seg_resumed = 0usize;
    for idx in 0..n_seg {
        let p = Path::new(OUT).join(format!("seg-{idx:03}.bin"));
        if let Some(_rct) = load_bincode::<SegmentReceipt>(&p) {
            n_seg_resumed += 1;
            csv_line(
                &mut csv,
                "seg",
                &idx.to_string(),
                0,
                fs::metadata(&p).map(|m| m.len() as usize).unwrap_or(0),
                true,
            );
            println!("seg {idx}/{n_seg}: resumed");
            continue;
        }
        let t = Instant::now();
        let seg = session.segments[idx].resolve().expect("resolve segment");
        let resolve_ms = t.elapsed().as_millis();
        csv_line(&mut csv, "resolve", &idx.to_string(), resolve_ms, 0, false);
        let t = Instant::now();
        let rct = server.prove_segment(&ctx, &seg).expect("prove segment");
        let ms = t.elapsed().as_millis();
        // 逐段 verify（与 segprove.rs verify1 同路径：verify_integrity_with_context）
        let t = Instant::now();
        rct.verify_integrity_with_context(&ctx)
            .expect("verify segment");
        let v_us = t.elapsed().as_micros();
        csv_line(&mut csv, "segverify", &idx.to_string(), v_us / 1000, 0, false);
        let ser = bincode::serialize(&rct).expect("ser seg");
        save_atomic(&p, &ser);
        csv_line(&mut csv, "seg", &idx.to_string(), ms, ser.len(), false);
        println!(
            "seg {idx}/{n_seg}: {ms} ms | verify {v_us} us | receipt {} B | VmHWM {} KB | elapsed {:.1} min",
            ser.len(),
            vm_hwm_kb(),
            t_start.elapsed().as_secs_f64() / 60.0
        );
    }
    drop(session);
    println!(
        "-- seg phase done: {n_seg_resumed} resumed | VmHWM {} KB | elapsed {:.1} min",
        vm_hwm_kb(),
        t_start.elapsed().as_secs_f64() / 60.0
    );

    // ---- 3. lift 全量（checkpoint 落盘）----
    let mut level: Vec<SuccinctReceipt<ReceiptClaim>> = Vec::with_capacity(n_seg);
    let mut n_lift_resumed = 0usize;
    for idx in 0..n_seg {
        let p = Path::new(OUT).join(format!("lift-{idx:03}.bin"));
        if let Some(s) = load_bincode::<SuccinctReceipt<ReceiptClaim>>(&p) {
            n_lift_resumed += 1;
            csv_line(
                &mut csv,
                "lift",
                &idx.to_string(),
                0,
                fs::metadata(&p).map(|m| m.len() as usize).unwrap_or(0),
                true,
            );
            level.push(s);
            println!("lift {idx}/{n_seg}: resumed");
            continue;
        }
        let segp = Path::new(OUT).join(format!("seg-{idx:03}.bin"));
        let seg: SegmentReceipt = load_bincode(&segp).expect("seg checkpoint missing");
        let t = Instant::now();
        let s = lift(&seg).expect("lift");
        let ms = t.elapsed().as_millis();
        let ser = bincode::serialize(&s).expect("ser lift");
        save_atomic(&p, &ser);
        csv_line(&mut csv, "lift", &idx.to_string(), ms, ser.len(), false);
        println!(
            "lift {idx}/{n_seg}: {ms} ms | receipt {} B | VmHWM {} KB",
            ser.len(),
            vm_hwm_kb()
        );
        level.push(s);
    }
    println!(
        "-- lift phase done: {n_lift_resumed} resumed | VmHWM {} KB | elapsed {:.1} min",
        vm_hwm_kb(),
        t_start.elapsed().as_secs_f64() / 60.0
    );

    // ---- 4. join 树（逐条 checkpoint；奇数进位节点由前轮 checkpoint 可再生）----
    let mut round = 0usize;
    let mut n_join_resumed = 0usize;
    while level.len() > 1 {
        let mut next: Vec<SuccinctReceipt<ReceiptClaim>> =
            Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        let mut j = 0usize;
        while i < level.len() {
            if i + 1 < level.len() {
                let p = Path::new(OUT).join(format!("join-r{round}-{j:03}.bin"));
                if let Some(node) = load_bincode::<SuccinctReceipt<ReceiptClaim>>(&p) {
                    n_join_resumed += 1;
                    csv_line(
                        &mut csv,
                        "join",
                        &format!("r{round}-{j}"),
                        0,
                        fs::metadata(&p).map(|m| m.len() as usize).unwrap_or(0),
                        true,
                    );
                    next.push(node);
                } else {
                    let t = Instant::now();
                    let node = join(&level[i], &level[i + 1]).expect("join");
                    let ms = t.elapsed().as_millis();
                    let ser = bincode::serialize(&node).expect("ser join");
                    save_atomic(&p, &ser);
                    csv_line(&mut csv, "join", &format!("r{round}-{j}"), ms, ser.len(), false);
                    println!(
                        "join r{round}-{j:03}: {ms} ms | receipt {} B | VmHWM {} KB",
                        ser.len(),
                        vm_hwm_kb()
                    );
                    next.push(node);
                }
                i += 2;
            } else {
                next.push(level[i].clone());
                i += 1;
            }
            j += 1;
        }
        level = next;
        println!(
            "-- join round r{round} done: {} nodes | VmHWM {} KB",
            level.len(),
            vm_hwm_kb()
        );
        round += 1;
    }
    let final_rct = level.pop().expect("final receipt");

    // ---- 5. final 落盘 + 全覆盖校验 ----
    let ser = bincode::serialize(&final_rct).expect("ser final");
    save_atomic(&Path::new(OUT).join("final.bin"), &ser);

    let t = Instant::now();
    final_rct
        .verify_integrity()
        .expect("verify final succinct (seal)");
    let integrity_us = t.elapsed().as_micros();

    let receipt = Receipt::new(InnerReceipt::Succinct(final_rct), journal_bytes.clone());
    let t = Instant::now();
    receipt.verify(image_id).expect("full verify (Receipt::verify)");
    let verify_us = t.elapsed().as_micros();
    let journal_ok = receipt.journal.bytes == expect_bytes;
    println!(
        "FINAL: receipt {} B | integrity {integrity_us} us | full verify {verify_us} us | journal_ok {journal_ok}",
        ser.len()
    );
    assert!(journal_ok, "journal mismatch vs host-expected public inputs");

    // ---- 6. 报告（从 CSV 汇总：同一 (phase,idx) 取最早的非 resumed 行）----
    use std::collections::BTreeMap;
    let csv_text = fs::read_to_string(format!("{OUT}/timing.csv")).unwrap_or_default();
    let mut chosen: BTreeMap<(String, String), (u128, usize, bool)> = BTreeMap::new();
    let mut n_sessions = 0usize;
    for line in csv_text.lines() {
        if line.starts_with("# session_start") {
            n_sessions += 1;
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        if f.len() != 7 {
            continue;
        }
        let key = (f[1].to_string(), f[2].to_string());
        let val = (
            f[3].parse::<u128>().unwrap_or(0),
            f[4].parse::<usize>().unwrap_or(0),
            f[6] == "1",
        );
        match chosen.get(&key) {
            None => {
                chosen.insert(key, val);
            }
            Some(&(_, _, prev_resumed)) if prev_resumed && !val.2 => {
                chosen.insert(key, val);
            }
            _ => {}
        }
    }

    let mut times: BTreeMap<String, Vec<u128>> = BTreeMap::new();
    let mut n_res: BTreeMap<String, usize> = BTreeMap::new();
    let mut bmin: BTreeMap<String, usize> = BTreeMap::new();
    let mut bmax: BTreeMap<String, usize> = BTreeMap::new();
    for ((phase, _), (ms, bytes, resumed)) in &chosen {
        if *resumed {
            *n_res.entry(phase.clone()).or_default() += 1;
        } else {
            times.entry(phase.clone()).or_default().push(*ms);
        }
        let lo = bmin.entry(phase.clone()).or_insert(usize::MAX);
        *lo = (*lo).min(*bytes);
        let hi = bmax.entry(phase.clone()).or_insert(0);
        *hi = (*hi).max(*bytes);
    }

    let mut rep = String::new();
    rep.push_str("full-v1 report (O2 batch)\n========================\n");
    rep.push_str(&format!(
        "elf: {elf_path} (user {} B) | po2={po2} | image_id={image_id}\n",
        user_elf.len()
    ));
    rep.push_str(&format!("segments: {n_seg}\n"));
    rep.push_str(&format!(
        "cycles: user={ucyc} paging={pcyc} reserved={rcyc} total={tcyc}\n"
    ));
    rep.push_str(&format!("sessions: {n_sessions} (resumed this session: seg={n_seg_resumed} lift={n_lift_resumed} join={n_join_resumed})\n"));
    for phase in ["exec", "resolve", "seg", "segverify", "lift", "join"] {
        if !chosen.keys().any(|(p, _)| p == phase) {
            continue;
        }
        let v = times.get(phase).cloned().unwrap_or_default();
        let n_c = v.len();
        let n_r = *n_res.get(phase).unwrap_or(&0);
        let sum: u128 = v.iter().sum();
        let mean = if n_c > 0 { sum / n_c as u128 } else { 0 };
        let (mn, mx) = (
            v.iter().min().copied().unwrap_or(0),
            v.iter().max().copied().unwrap_or(0),
        );
        rep.push_str(&format!(
            "{phase}: computed={n_c} resumed={n_r} total_ms={sum} mean_ms={mean} median_ms={} min_ms={mn} max_ms={mx} bytes=[{},{}]\n",
            median(&v),
            bmin.get(phase).copied().unwrap_or(0),
            bmax.get(phase).copied().unwrap_or(0)
        ));
    }
    rep.push_str(&format!(
        "final: receipt_bytes={} integrity_us={integrity_us} verify_us={verify_us} journal_ok={journal_ok}\n",
        ser.len()
    ));
    rep.push_str(&format!(
        "wall_this_session_min: {:.2}\n",
        t_start.elapsed().as_secs_f64() / 60.0
    ));
    let _ = writeln!(
        csv,
        "# session_end ts={} wall_min={:.2}",
        now_ts(),
        t_start.elapsed().as_secs_f64() / 60.0
    );
    fs::write(format!("{OUT}/report.txt"), &rep).expect("write report");
    println!("{rep}");
    println!("=== full-v1 done ===");
}
