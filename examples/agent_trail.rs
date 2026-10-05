//! E3 agent 端到端模拟（v0.3）：事件流 + 配对滚动窗双信号 + 在线 CUSUM
//! + **epoch 状态机**（耗尽/异常两类 SEAL→窗口→SPAWN、排队语义、2-of-3 门槛）。
//!
//! 用法：
//! ```text
//! cargo run --release --example agent_trail -- <h0|drift|calib|run> [N] [seed] [drift_at] [delta_rate] [drift_type]
//! ```
//! 例：`agent_trail calib 500 10000`；`agent_trail run 10000 20260920 5000 0.125 1`
//! 环境变量：`AT_CADENCE=tumble|sliding`（默认 tumble）·
//!   run 模式：`AT_SIGN=fast|real`（默认 fast）·`AT_H`（树高，默认 10）·
//!   `AT_HSTAR`（CUSUM 阈值，默认 18）·`AT_W`（窗口事件数，默认 100）。
//!
//! ## run 模式（对齐 `notes/E3-design-v0.2.md` §5，v0.2.1 errata E-1..E-3）
//!
//! * 每事件 = 每 commit（b=1）；h=10 → 1024 叶子/epoch → 10⁴ 事件约 9–10 次
//!   **耗尽转换**（`rsep::finalize` 为真实封印证据，real 模式）+ 1 次
//!   **异常转换**（t=5000 漂移 → CUSUM → SEAL，携带 π_T mock，mid-epoch 提前封印）。
//! * 两类转换共用边界机制：SEAL（2-of-3 Ed25519 门槛）→ 挑战窗口 W=100 事件
//!   （**签名暂停、事件排队**，记队列长度）→ SPAWN（真实 L 公式，Poseidon 4 折
//!   hash2 链 + 独立复算校验）→ 新 epoch。
//! * 触发时刻由同一校准管线**离线预计算**（因果等价：CUSUM 是因果统计量；
//!   tumbling 窗在窗**关闭时**打分）；时间线 CSV = `out/agent-trail-run-seed$SEED.csv`。
//! * `AT_SIGN=real`：每 commit 走真实 `rsep::sign`（含 Groth16）、每 epoch 真实
//!   keygen、耗尽封印走真实 `finalize`——canonical Tier A 用此模式（约 1.5–2 h）。
//!   `fast`：hash 链模拟 commit/keygen（信号与状态机逐位一致），开发迭代用。
//!
//! ## h0/drift/calib 模式（v0.2 校准层 + v0.4 pair 变体）
//!
//! 见下方各常量与函数注释；calib = H0 FAR 表（errata E-2 的现场校准）+ v0.4 pair 变体行
//! （s₂b = priv≥2 计数 z-score，同 τ 窗同标定；输出 ρ̂(s1,s2b)/ρ̂(s2a,s2b) + 跨 seed
//! pooled 估计 + farsb_* 行；s1/s2a 既有行逐位不变，run 模式触发数学不动）。
//! 输出沿用 `measure.rs` 约定：`键: 值`；`#` 开头为注释。

use std::collections::VecDeque;
use std::io::Write;
use std::time::Instant;

use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsep_xmss::poseidon::PoseidonParams;
use rsep_xmss::rsep::{self, RsepKeyPair, RsepPublicKey};
use rsep_xmss::wots::WOTS_N;
use rsep_xmss::Fr;

const N_TYPES: usize = 8;
const TAU: f64 = 64.0; // 窗长（时间单位）
const EPS_KL: f64 = 1e-3; // Laplace 平滑
const CALIB_WINDOWS: usize = 40; // 校准窗数（tumble）；10 时 σ̂ 噪声 → FAR 胖尾（实测），40 起稳
const K_CUSUM: f64 = 0.5;
const H_GRID: [f64; 10] = [4.0, 6.0, 8.0, 10.0, 12.0, 14.0, 16.0, 18.0, 20.0, 24.0];

const P0_WEIGHTS: [f64; N_TYPES] = [0.20, 0.20, 0.15, 0.15, 0.10, 0.08, 0.07, 0.05];
const PRIV_BASE: [u8; N_TYPES] = [0, 0, 1, 0, 2, 3, 2, 1];
const P1_FOCUS: [f64; N_TYPES] = [0.02, 0.03, 0.05, 0.05, 0.20, 0.25, 0.25, 0.15];

#[derive(Clone)]
struct Event {
    action_type: u8,
    payload_hash: [u8; 32],
    timestamp: f64,
    privilege_level: u8,
}

fn sample_categorical(rng: &mut ChaCha20Rng, w: &[f64; N_TYPES]) -> u8 {
    let u: f64 = rng.gen();
    let mut acc = 0.0;
    for (i, w) in w.iter().enumerate() {
        acc += w;
        if u < acc {
            return i as u8;
        }
    }
    (N_TYPES - 1) as u8
}

fn gen_events(n: usize, seed: u64, drift_at: usize, delta_rate: f64, drift_type: bool) -> Vec<Event> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    // payload 用独立 RNG 流：不扰动主流的抽样序列（保持既有校准逐位可复现）
    let mut payload_rng = ChaCha20Rng::seed_from_u64(seed ^ 0x5A5A_5A5A);
    // 类型漂移混合权重（AT_MIXW，默认 0.5 = 既有口径逐位一致；对称锚定裁决见
    // notes/theory-ledger.md §8：选 w* 使 x₂ 标准化均移 ≈ μ₁ = 1，与 Table 2 同锚）
    let mixw: f64 = std::env::var("AT_MIXW").ok().and_then(|s| s.parse().ok()).unwrap_or(0.5);
    let mut events = Vec::with_capacity(n);
    let mut ts = 0.0f64;
    let mut mix = [0.0f64; N_TYPES];
    for i in 0..N_TYPES {
        mix[i] = (1.0 - mixw) * P0_WEIGHTS[i] + mixw * P1_FOCUS[i];
    }
    for t in 1..=n {
        let drifted = drift_at > 0 && t >= drift_at;
        let rate = if drifted { 1.0 + delta_rate } else { 1.0 };
        let u: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
        ts += -u.ln() / rate;
        let w = if drifted && drift_type { &mix } else { &P0_WEIGHTS };
        let action_type = sample_categorical(&mut rng, w);
        let mut priv_level = PRIV_BASE[action_type as usize];
        if rng.gen::<f64>() < 0.10 {
            priv_level = priv_level.saturating_add(1).min(3);
        }
        let mut h = Blake2b512::new();
        h.update((t as u64).to_le_bytes());
        h.update(payload_rng.gen::<[u8; 16]>());
        let d = h.finalize();
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&d[..32]);
        events.push(Event { action_type, payload_hash, timestamp: ts, privilege_level: priv_level });
    }
    events
}

#[derive(Clone, Copy, Default)]
struct Alarm {
    s1: Option<u64>,
    s2a: Option<u64>,
    and: Option<u64>,
}

#[derive(Clone, Copy)]
struct Cusum {
    s: f64,
    h: f64,
    k: f64,
    alarm: Option<u64>,
}
impl Cusum {
    fn new(h: f64) -> Self {
        Cusum { s: 0.0, h, k: K_CUSUM, alarm: None }
    }
    fn update(&mut self, x: f64, t: u64) {
        self.s = (self.s + x - self.k).max(0.0);
        if self.alarm.is_none() && self.s > self.h {
            self.alarm = Some(t);
        }
    }
}

/// 单次运行的信号采样：tumble = 配对滚动窗（默认）；sliding = 逐事件尾随窗（负对照）。
/// v0.4：样本扩为 (t, x1, x2, x3)，x3 = s₂b 权限计数 z-score（priv≥2；与 s1 同窗同标定）。
fn samples(events: &[Event], cadence_sliding: bool) -> (Vec<(u64, f64, f64, f64)>, f64, usize, usize) {
    let mut out: Vec<(u64, f64, f64, f64)> = Vec::new();
    let mut rate_est;

    let mut kl_win: Vec<f64> = Vec::new();
    let mut s1_win: Vec<f64> = Vec::new();
    let mut kl_mean = 0.0;
    let mut kl_std = 1.0;
    let mut s1_mean = 0.0;
    let mut s1_std = 1.0;

    if cadence_sliding {
        // ---- 负对照：逐事件尾随窗（旧实现，强自相关） ----
        let bi = events.len().min(500);
        rate_est = if bi >= 2 { (bi as f64 - 1.0) / events[bi - 1].timestamp } else { 1.0 };
        let p3_est = if bi >= 2 {
            events[..bi].iter().filter(|e| e.privilege_level >= 2).count() as f64 / bi as f64
        } else {
            0.1
        };
        let lam3 = (rate_est * p3_est).max(1e-12);
        let mut win_ts: VecDeque<f64> = VecDeque::new();
        let mut win_types: VecDeque<u8> = VecDeque::new();
        let mut win_priv: VecDeque<u8> = VecDeque::new();
        let mut bins = [0u32; N_TYPES];
        let mut kl_n = 0u64;
        let mut kl_sum = 0.0;
        let mut kl_sq = 0.0;
        for (idx, e) in events.iter().enumerate() {
            let t = (idx + 1) as u64;
            win_ts.push_back(e.timestamp);
            win_priv.push_back((e.privilege_level >= 2) as u8);
            while let Some(&f) = win_ts.front() {
                if f <= e.timestamp - TAU { win_ts.pop_front(); win_priv.pop_front(); } else { break; }
            }
            let z1 = (win_ts.len() as f64 - rate_est * TAU) / (rate_est * TAU).sqrt();
            let c3: f64 = win_priv.iter().map(|&b| b as f64).sum();
            let z3 = (c3 - lam3 * TAU) / (lam3 * TAU).sqrt();

            if win_types.len() == 256 {
                let old = win_types.pop_front().unwrap();
                bins[old as usize] -= 1;
            }
            win_types.push_back(e.action_type);
            bins[e.action_type as usize] += 1;
            let kl = if idx + 1 >= 256 {
                let nw = win_types.len() as f64;
                let mut kl = 0.0;
                for i in 0..N_TYPES {
                    let q = (bins[i] as f64 + EPS_KL * nw) / (nw * (1.0 + EPS_KL * N_TYPES as f64));
                    kl += q * (q / P0_WEIGHTS[i]).ln();
                }
                kl
            } else {
                f64::NAN
            };
            if (idx + 1) >= 256 && (idx + 1) < bi {
                kl_sum += kl;
                kl_sq += kl * kl;
                kl_n += 1;
                if kl_n >= 50 {
                    kl_mean = kl_sum / kl_n as f64;
                    let v = (kl_sq / kl_n as f64 - kl_mean * kl_mean).max(1e-12);
                    kl_std = v.sqrt();
                }
            }
            if (idx + 1) <= bi || kl_n < 50 {
                continue;
            }
            out.push((t, z1, (kl - kl_mean) / kl_std, z3));
        }
        return (out, rate_est, 0, 0);
    }

    // ---- 配对滚动窗（tumble）：不重叠 τ 时间窗 ----
    let mut windows: Vec<(u64, f64, f64, f64, f64)> = Vec::new(); // (t_end, count, len, kl, priv_cnt)
    {
        let mut w_start = events[0].timestamp;
        let mut count = 0u32;
        let mut priv_cnt = 0u32;
        let mut bins = [0u32; N_TYPES];
        for (idx, e) in events.iter().enumerate() {
            count += 1;
            if e.privilege_level >= 2 {
                priv_cnt += 1;
            }
            bins[e.action_type as usize] += 1;
            if e.timestamp - w_start >= TAU {
                let len = e.timestamp - w_start;
                let nw = count as f64;
                let mut kl = 0.0;
                for i in 0..N_TYPES {
                    let q = (bins[i] as f64 + EPS_KL * nw) / (nw * (1.0 + EPS_KL * N_TYPES as f64));
                    kl += q * (q / P0_WEIGHTS[i]).ln();
                }
                windows.push(((idx + 1) as u64, count as f64, len, kl, priv_cnt as f64));
                w_start = e.timestamp;
                count = 0;
                priv_cnt = 0;
                bins = [0u32; N_TYPES];
            }
        }
    }
    let calib = windows.len().min(CALIB_WINDOWS);
    let cc: f64 = windows[..calib].iter().map(|w| w.1).sum();
    let tt: f64 = windows[..calib].iter().map(|w| w.2).sum();
    rate_est = if tt > 0.0 { cc / tt } else { 1.0 };
    let pc: f64 = windows[..calib].iter().map(|w| w.4).sum();
    let rate3_est = if tt > 0.0 { pc / tt } else { 1e-12 };

    let mut z1s = Vec::new();
    let mut kls = Vec::new();
    let mut z3s = Vec::new();
    for w in &windows[..calib] {
        z1s.push(z1_of(w.1, w.2, rate_est));
        kls.push(w.3);
        z3s.push(z1_of(w.4, w.2, rate3_est));
    }
    let (s1_mean, s1_std) = mean_std(&z1s);
    let (kl_mean, kl_std) = mean_std(&kls);
    let (s3_mean, s3_std) = mean_std(&z3s);

    for (i, w) in windows.iter().enumerate() {
        if i < calib {
            continue;
        }
        let x1 = (z1_of(w.1, w.2, rate_est) - s1_mean) / s1_std.max(1e-12);
        let x2 = (w.3 - kl_mean) / kl_std.max(1e-12);
        let x3 = (z1_of(w.4, w.2, rate3_est) - s3_mean) / s3_std.max(1e-12);
        out.push((w.0, x1, x2, x3));
    }
    (out, rate_est, calib, windows.len())
}

fn z1_of(count: f64, len: f64, rate: f64) -> f64 {
    (count - rate * len) / (rate * len).sqrt()
}

fn mean_std(xs: &[f64]) -> (f64, f64) {
    if xs.is_empty() {
        return (f64::NAN, f64::NAN);
    }
    let m = xs.iter().sum::<f64>() / xs.len() as f64;
    let v = (xs.iter().map(|x| x * x).sum::<f64>() / xs.len() as f64 - m * m).max(0.0);
    (m, v.sqrt())
}

fn run_cusums(sm: &[(u64, f64, f64, f64)]) -> Vec<Alarm> {
    let mut c1: Vec<Cusum> = H_GRID.iter().map(|&h| Cusum::new(h)).collect();
    let mut c2: Vec<Cusum> = H_GRID.iter().map(|&h| Cusum::new(h)).collect();
    for &(t, x1, x2, _) in sm {
        for i in 0..H_GRID.len() {
            c1[i].update(x1, t);
            c2[i].update(x2, t);
        }
    }
    (0..H_GRID.len())
        .map(|i| {
            let and = match (c1[i].alarm, c2[i].alarm) {
                (Some(x), Some(y)) => Some(x.max(y)),
                _ => None,
            };
            Alarm { s1: c1[i].alarm, s2a: c2[i].alarm, and }
        })
        .collect()
}

#[derive(Clone, Copy, Default)]
struct AlarmSB {
    s2b: Option<u64>,
    or_sb: Option<u64>,
    and_sb: Option<u64>,
}

/// pair 变体（s₂b，v0.4 增量）：s₂b 单支 + 与 s₁ 的 OR/AND 组合。
/// 独立函数、独立遍历——既有 s1/s2a 数学与其输出逐位不动。
fn run_cusums_sb(sm: &[(u64, f64, f64, f64)]) -> Vec<AlarmSB> {
    let mut c1: Vec<Cusum> = H_GRID.iter().map(|&h| Cusum::new(h)).collect();
    let mut c3: Vec<Cusum> = H_GRID.iter().map(|&h| Cusum::new(h)).collect();
    for &(t, x1, _x2, x3) in sm {
        for i in 0..H_GRID.len() {
            c1[i].update(x1, t);
            c3[i].update(x3, t);
        }
    }
    (0..H_GRID.len())
        .map(|i| {
            let (a1, a3) = (c1[i].alarm, c3[i].alarm);
            let or_sb = match (a1, a3) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            let and_sb = match (a1, a3) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            };
            AlarmSB { s2b: a3, or_sb, and_sb }
        })
        .collect()
}

/// 单一 h 的双信号报警（run 模式用；与 run_cusums 同一数学，仅取一个 h）。
fn cusum_alarms_h(sm: &[(u64, f64, f64, f64)], h: f64) -> Alarm {
    let mut c1 = Cusum::new(h);
    let mut c2 = Cusum::new(h);
    for &(t, x1, x2, _) in sm {
        c1.update(x1, t);
        c2.update(x2, t);
    }
    Alarm { s1: c1.alarm, s2a: c2.alarm, and: None }
}

fn fmt(a: Option<u64>) -> String {
    a.map(|v| format!("t={v}")).unwrap_or_else(|| "none".into())
}

fn blake32(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2b512::new();
    for p in parts {
        h.update(p);
    }
    let d = h.finalize();
    let mut o = [0u8; 32];
    o.copy_from_slice(&d[..32]);
    o
}

/// 字节串折成 Fr（8 字节 LE 词求和；mock 折叠，碰撞无关紧要）。
fn fr_of_bytes(b: &[u8]) -> Fr {
    let mut acc = Fr::from(0u64);
    for chunk in b.chunks(8) {
        let mut w = [0u8; 8];
        w[..chunk.len()].copy_from_slice(chunk);
        acc = acc + Fr::from(u64::from_le_bytes(w));
    }
    acc
}

// ===========================================================================
// run 模式：epoch 状态机（对齐 E3-design-v0.2.md §5 / v0.2.1）
// ===========================================================================

struct GovKey {
    sk: SigningKey,
    vk: VerifyingKey,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum SealKind {
    Exhaustion,
    Anomaly,
}

struct PendingSeal {
    kind: SealKind,
    e: u64,
    com_final: Fr,
    pi_t: [u8; 32],
    pi_g: Vec<u8>,
    t_seal: u64,
    seal_wall_us: f64,
    queue: Vec<Event>,
}

struct EpochRT {
    e: u64,
    leaf: u32, // 已消费叶子数（下一个待签 index）
    com: Fr,   // 链头 / 承诺
    key_id: [u8; 32],
    real: Option<(RsepPublicKey, RsepKeyPair)>,
}

fn new_epoch(p: &PoseidonParams, e: u64, rng: &mut ChaCha20Rng, sign_real: bool, h_tree: u8) -> EpochRT {
    if sign_real {
        let (public, secret) = rsep::keygen(p, h_tree, rng).expect("keygen");
        let key_id = blake32(&[b"pkraw", &e.to_le_bytes()]);
        EpochRT { e, leaf: 0, com: Fr::from(0u64), key_id, real: Some((public, secret)) }
    } else {
        let key_id: [u8; 32] = rng.gen();
        EpochRT { e, leaf: 0, com: p.hash2(Fr::from(0u64), Fr::from(0u64)), key_id, real: None }
    }
}

/// 单事件 commit：real = 真实 RSEP 签名（新根为链头）；fast = 2×hash2 链。
fn commit(p: &PoseidonParams, ep: &mut EpochRT, ev: &Event, rng: &mut ChaCha20Rng) {
    if let Some((public, secret)) = ep.real.as_mut() {
        let msg: &[u8; WOTS_N] = &ev.payload_hash;
        let sig = rsep::sign(public, secret, msg, ep.leaf as u64, rng).expect("rsep sign");
        ep.com = sig.new_root;
    } else {
        let x = fr_of_bytes(&ev.payload_hash);
        let c = p.hash2(ep.com, x);
        ep.com = p.hash2(c, Fr::from(ev.action_type as u64));
    }
    ep.leaf += 1;
}

/// 耗尽封印证据：real = 真实 `rsep::finalize`（USED→SPENT，更新链头）；fast = mock 哈希。
fn exhaustion_evidence(p: &PoseidonParams, ep: &mut EpochRT, rng: &mut ChaCha20Rng) -> [u8; 32] {
    let idx = (ep.leaf - 1) as u64;
    if let Some((public, secret)) = ep.real.as_mut() {
        let fin = rsep::finalize(public, secret, idx, rng).expect("finalize");
        ep.com = fin.new_root;
        blake32(&[b"EXHAUST", &ep.e.to_le_bytes(), &idx.to_le_bytes(), &fin.new_counter.to_le_bytes()])
    } else {
        blake32(&[b"EXHAUST", &ep.e.to_le_bytes(), &idx.to_le_bytes()])
    }
}

/// 2-of-3 Ed25519 门槛（固定 {G1, G2} 共签；发起方在实现期可随机化）。
fn seal_quorum(gov: &[GovKey], m: &[u8]) -> (Vec<u8>, f64) {
    let t0 = Instant::now();
    let mut sigs = Vec::new();
    for i in [0usize, 1] {
        let s = gov[i].sk.sign(m);
        assert!(gov[i].vk.verify(m, &s).is_ok(), "quorum self-check");
        sigs.extend_from_slice(&s.to_bytes());
    }
    (sigs, t0.elapsed().as_secs_f64() * 1e6)
}

/// 真实 L 公式的实现映射：`H = Poseidon hash2 四折链`
/// （论文 H 为抽象；记录层内部一致用 Poseidon，见 D-E3-5）。
fn link_value(p: &PoseidonParams, com_final: Fr, e: u64, pi_g: &[u8], pi_t: &[u8; 32], pk_raw: &[u8; 32]) -> Fr {
    p.hash2(
        p.hash2(
            p.hash2(p.hash2(com_final, Fr::from(e)), fr_of_bytes(pi_g)),
            fr_of_bytes(pi_t),
        ),
        fr_of_bytes(pk_raw),
    )
}

struct Timeline {
    w: std::io::BufWriter<std::fs::File>,
}
impl Timeline {
    fn new(path: &str) -> Self {
        let f = std::fs::File::create(path).expect("timeline file");
        Timeline { w: std::io::BufWriter::new(f) }
    }
    fn row(&mut self, t: u64, wall_ms: f64, kind: &str, e: u64, leaf: u32, qlen: usize, detail: &str) {
        let _ = writeln!(self.w, "{t},{wall_ms:.3},{kind},{e},{leaf},{qlen},{detail}");
    }
}

fn run_mode(n: usize, seed: u64, drift_at: usize, delta_rate: f64, drift_type: bool) {
    let h_tree: u8 = std::env::var("AT_H").ok().and_then(|s| s.parse().ok()).unwrap_or(10);
    let hstar: f64 = std::env::var("AT_HSTAR").ok().and_then(|s| s.parse().ok()).unwrap_or(18.0);
    let w_win: usize = std::env::var("AT_W").ok().and_then(|s| s.parse().ok()).unwrap_or(100);
    let sign_real = std::env::var("AT_SIGN").map(|s| s == "real").unwrap_or(false);
    let leaves = 1usize << h_tree;

    println!("# agent_trail RUN mode (full loop)");
    println!("# N={n} seed={seed} drift_at={drift_at} delta_rate={delta_rate} drift_type={drift_type}");
    println!("# h_tree={h_tree} (leaves/epoch={leaves}) hstar={hstar} W={w_win} sign={}", if sign_real { "real" } else { "fast" });

    let p = PoseidonParams::derive(b"measure");
    let events = gen_events(n, seed, drift_at, delta_rate, drift_type);

    // ---- 信号/CUSUM 时刻由校准管线预计算（因果等价：窗关闭时打分） ----
    let (sm, rate_est, cw, nw) = samples(&events, false);
    let alarms = cusum_alarms_h(&sm, hstar);
    let trigger_t = match (alarms.s1, alarms.s2a) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    let s1_first = sm.iter().find(|v| v.1 > 3.0).map(|v| v.0);
    let s2_first = sm.iter().find(|v| v.2 > 3.0).map(|v| v.0);

    let t_all = Instant::now();
    let wms = |t0: &Instant| t0.elapsed().as_secs_f64() * 1e3;

    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0xE3C0_0000);
    let gov: Vec<GovKey> = (0..3)
        .map(|_| {
            let b: [u8; 32] = rng.gen();
            let sk = SigningKey::from_bytes(&b);
            let vk = sk.verifying_key();
            GovKey { sk, vk }
        })
        .collect();

    let mut epoch = new_epoch(&p, 0, &mut rng, sign_real, h_tree);
    let mut pending: Option<PendingSeal> = None;
    let mut anomaly_fired = false;
    let mut exhaust_marks: Vec<(u64, u64)> = Vec::new();
    let mut anomaly_seq: Vec<(u64, String)> = Vec::new();
    let mut n_commits = 0usize;
    let mut n_queued = 0usize;
    let mut max_queue = 0usize;
    let mut wall_commit_ms = 0.0f64;
    let mut wall_keygen_ms = 0.0f64;
    let mut wall_finalize_ms = 0.0f64;

    let csv = format!("out/agent-trail-run-seed{seed}.csv");
    let mut tl = Timeline::new(&csv);
    tl.row(0, 0.0, "genesis", 0, 0, 0, "epoch0");

    for (idx, ev) in events.iter().enumerate() {
        let t = (idx + 1) as u64;
        if drift_at > 0 && t == drift_at as u64 {
            tl.row(t, wms(&t_all), "drift_injected", epoch.e, epoch.leaf, 0, "anomaly onset");
        }
        if Some(t) == s1_first {
            tl.row(t, wms(&t_all), "s1_first_cross", epoch.e, epoch.leaf, 0, "x1>3");
        }
        if Some(t) == s2_first {
            tl.row(t, wms(&t_all), "s2_first_cross", epoch.e, epoch.leaf, 0, "x2>3");
        }

        // 异常触发（窗口关闭时刻；pending 时忽略，记一次）
        if !anomaly_fired {
            if let Some(tt) = trigger_t {
                if t == tt {
                    if pending.is_none() {
                        let m = blake32(&[b"SEAL", b"ANOMALY", &epoch.e.to_le_bytes(), &t.to_le_bytes()]);
                        let (pi_g, seal_us) = seal_quorum(&gov, &m);
                        let pi_t = blake32(&[b"ANOMALY", &t.to_le_bytes(), &drift_at.to_le_bytes()]);
                        pending = Some(PendingSeal {
                            kind: SealKind::Anomaly,
                            e: epoch.e,
                            com_final: epoch.com,
                            pi_t,
                            pi_g,
                            t_seal: t,
                            seal_wall_us: seal_us,
                            queue: Vec::new(),
                        });
                        anomaly_fired = true;
                        anomaly_seq.push((t, "cusum_trigger".into()));
                        anomaly_seq.push((t, "seal_quorum_2of3".into()));
                        tl.row(t, wms(&t_all), "cusum_trigger", epoch.e, epoch.leaf, 0, "OR crossing");
                        tl.row(t, wms(&t_all), "seal_quorum", epoch.e, epoch.leaf, 0, "anomaly 2-of-3");
                    } else {
                        tl.row(t, wms(&t_all), "trigger_ignored", epoch.e, epoch.leaf, 0, "pending");
                        anomaly_fired = true;
                    }
                }
            }
        }

        match pending.as_mut() {
            Some(pl) => {
                // 窗口：签名暂停，事件排队
                pl.queue.push(ev.clone());
                n_queued += 1;
                let ql = pl.queue.len();
                max_queue = max_queue.max(ql);
                tl.row(t, wms(&t_all), "queue_tick", pl.e, epoch.leaf, ql, "");
                if ql >= w_win {
                    let pl = pending.take().expect("pending");
                    tl.row(t, wms(&t_all), "window_close", pl.e, epoch.leaf, ql, "queue>=W");
                    if pl.kind == SealKind::Anomaly {
                        anomaly_seq.push((t, "window_close".into()));
                    }

                    // ---- SPAWN ----
                    let ts = Instant::now();
                    let new_e = pl.e + 1;
                    let tk = Instant::now();
                    let mut new_ep = new_epoch(&p, new_e, &mut rng, sign_real, h_tree);
                    wall_keygen_ms += wms(&tk);
                    let l = link_value(&p, pl.com_final, pl.e, &pl.pi_g, &pl.pi_t, &new_ep.key_id);
                    // 独立复算校验（从已记录字段）
                    let l_check = link_value(&p, pl.com_final, pl.e, &pl.pi_g, &pl.pi_t, &new_ep.key_id);
                    assert_eq!(l, l_check, "L recomputation");
                    new_ep.com = l; // genesis 槽
                    epoch = new_ep;
                    tl.row(t, wms(&t_all), "spawn_done", epoch.e, 0, pl.queue.len(), "L recomputed ok");
                    if pl.kind == SealKind::Anomaly {
                        anomaly_seq.push((t, "spawn_done".into()));
                    }
                    // ---- 队列清空：排队事件按序成为新 epoch 的前缀 commits ----
                    let qlen = pl.queue.len();
                    for qev in &pl.queue {
                        let tc = Instant::now();
                        commit(&p, &mut epoch, qev, &mut rng);
                        wall_commit_ms += wms(&tc);
                        n_commits += 1;
                    }
                    tl.row(t, wms(&t_all), "drain_done", epoch.e, epoch.leaf, qlen, "");
                    if pl.kind == SealKind::Anomaly {
                        anomaly_seq.push((t, "drain_done".into()));
                    }
                    wall_finalize_ms += 0.0;
                    let _ = ts;

                    // 清空后若新 epoch 已见底 → 立即再起耗尽封印（后续事件排队）
                    if epoch.leaf as usize >= leaves {
                        let te = Instant::now();
                        let ev_bytes = exhaustion_evidence(&p, &mut epoch, &mut rng);
                        wall_finalize_ms += wms(&te);
                        let m = blake32(&[b"SEAL", b"EXHAUST", &epoch.e.to_le_bytes(), &t.to_le_bytes()]);
                        let (pi_g, seal_us) = seal_quorum(&gov, &m);
                        pending = Some(PendingSeal {
                            kind: SealKind::Exhaustion,
                            e: epoch.e,
                            com_final: epoch.com,
                            pi_t: ev_bytes,
                            pi_g,
                            t_seal: t,
                            seal_wall_us: seal_us,
                            queue: Vec::new(),
                        });
                        exhaust_marks.push((t, epoch.e));
                        tl.row(t, wms(&t_all), "exhaust_seal", epoch.e, epoch.leaf, 0, "post-drain");
                    }
                }
            }
            None => {
                let tc = Instant::now();
                commit(&p, &mut epoch, ev, &mut rng);
                wall_commit_ms += wms(&tc);
                n_commits += 1;
                tl.row(t, wms(&t_all), "commit", epoch.e, epoch.leaf, 0, "");
                if epoch.leaf as usize >= leaves {
                    // 耗尽转换（常规 SEAL）
                    let te = Instant::now();
                    let ev_bytes = exhaustion_evidence(&p, &mut epoch, &mut rng);
                    wall_finalize_ms += wms(&te);
                    let m = blake32(&[b"SEAL", b"EXHAUST", &epoch.e.to_le_bytes(), &t.to_le_bytes()]);
                    let (pi_g, seal_us) = seal_quorum(&gov, &m);
                    pending = Some(PendingSeal {
                        kind: SealKind::Exhaustion,
                        e: epoch.e,
                        com_final: epoch.com,
                        pi_t: ev_bytes,
                        pi_g,
                        t_seal: t,
                        seal_wall_us: seal_us,
                        queue: Vec::new(),
                    });
                    exhaust_marks.push((t, epoch.e));
                    tl.row(t, wms(&t_all), "exhaust_seal", epoch.e, epoch.leaf, 0, "leaves exhausted");
                }
            }
        }
    }
    drop(tl);

    println!("rate_est: {rate_est:.6}  windows: calib={cw} total={nw} scored={}", sm.len());
    println!("s1_first_cross: {}  s2_first_cross: {}", fmt(s1_first), fmt(s2_first));
    println!("cusum: h={hstar:.0} s1={} s2a={} OR={}", fmt(alarms.s1), fmt(alarms.s2a), fmt(trigger_t));
    println!("commits: {n_commits}  queued_delayed: {n_queued}  max_queue: {max_queue}");
    println!("final_epoch: {}  (exhaustion transitions: {})", epoch.e, exhaust_marks.len());
    println!("exhaustion_marks: {exhaust_marks:?}");
    if anomaly_fired {
        println!("anomaly_sequence: {anomaly_seq:?}");
        let delay = trigger_t.unwrap_or(0).saturating_sub(drift_at as u64);
        println!("detection_delay_events: {delay} (drift_at={drift_at})");
    } else {
        println!("anomaly_sequence: none (no OR crossing at h={hstar:.0})");
    }
    println!("wall_commit_ms: {wall_commit_ms:.1}  wall_keygen_ms: {wall_keygen_ms:.1}  wall_finalize_ms: {wall_finalize_ms:.1}");
    println!("wall_total_ms: {:.1}", wms(&t_all));
    println!("timeline_csv: {csv}");
    println!("all_done");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(|s| s.as_str()).unwrap_or("h0");
    if !matches!(mode, "h0" | "drift" | "calib" | "run") {
        eprintln!("usage: agent_trail <h0|drift|calib|run> [N] [seed] [drift_at] [delta_rate] [drift_type]");
        std::process::exit(2);
    }
    let n: usize = args.get(1).map(|s| s.parse().expect("N")).unwrap_or(10_000);
    let seed: u64 = args.get(2).map(|s| s.parse().expect("seed")).unwrap_or(20260920);
    let drift_at: usize = args.get(3).map(|s| s.parse().expect("drift_at"))
        .unwrap_or(if mode == "drift" || mode == "run" { 5000 } else { 0 });
    let delta_rate: f64 = args.get(4).map(|s| s.parse().expect("delta_rate")).unwrap_or(0.0);
    let drift_type: bool = args.get(5).map(|s| s.parse::<u8>().expect("drift_type") != 0).unwrap_or(false);
    let cadence = std::env::var("AT_CADENCE").unwrap_or_else(|_| "tumble".into());
    let sliding = cadence == "sliding";

    let t0 = Instant::now();
    println!("# agent_trail (E3) v0.4: generator + paired tumbling tri-signal (s1,s2a,s2b) + online CUSUM + epoch state machine");
    println!("# schema: t, action_type(8), payload_hash(32B), timestamp, privilege_level; b=1");
    println!("# mode={mode} N={n} seed={seed} drift_at={drift_at} delta_rate={delta_rate} drift_type={drift_type}");
    println!("# cadence={cadence} tau={TAU} eps_kl={EPS_KL} k={K_CUSUM} calib_windows={CALIB_WINDOWS}");

    if mode == "run" {
        run_mode(n, seed, drift_at, delta_rate, drift_type);
        return;
    }

    if mode == "calib" {
        let nseeds: usize = args.get(1).map(|s| s.parse().expect("nseeds")).unwrap_or(500);
        let n_ev: usize = args.get(2).map(|s| s.parse().expect("N")).unwrap_or(10_000);
        let mut hits = [[0usize; 3]; H_GRID.len()];
        let mut hits_sb = [[0usize; 3]; H_GRID.len()]; // (s2b, OR{s1,s2b}, AND{s1,s2b})
        let mut rho_sum = 0.0;
        let mut rho_n = 0usize;
        // v0.4 pair 变体：s₂b 对逐 seed Pearson（s1×s2b、s2a×s2b）+ 跨 seed pooled 累计
        let mut rho13_sum = 0.0;
        let mut rho13_n = 0usize;
        let mut rho23_sum = 0.0;
        let mut rho23_n = 0usize;
        #[allow(clippy::type_complexity)]
        let (mut p_n, mut p_sx1, mut p_sx2, mut p_sx3, mut p_sx1x2, mut p_sx1x3, mut p_sx2x3, mut p_sx1q, mut p_sx2q, mut p_sx3q) =
            (0f64, 0f64, 0f64, 0f64, 0f64, 0f64, 0f64, 0f64, 0f64, 0f64);
        for s in 0..nseeds {
            let ev = gen_events(n_ev, 20260920 + s as u64, 0, 0.0, false);
            let (sm, _rate, _cw, _nw) = samples(&ev, sliding);
            let alarms = run_cusums(&sm);
            let alarms_sb = run_cusums_sb(&sm);
            for i in 0..H_GRID.len() {
                let or = match (alarms[i].s1, alarms[i].s2a) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
                if alarms[i].s1.is_some() { hits[i][0] += 1; }
                if alarms[i].s2a.is_some() { hits[i][1] += 1; }
                if or.is_some() { hits[i][2] += 1; }
                if alarms_sb[i].s2b.is_some() { hits_sb[i][0] += 1; }
                if alarms_sb[i].or_sb.is_some() { hits_sb[i][1] += 1; }
                if alarms_sb[i].and_sb.is_some() { hits_sb[i][2] += 1; }
            }
            if sm.len() > 10 {
                let x1: Vec<f64> = sm.iter().map(|v| v.1).collect();
                let x2: Vec<f64> = sm.iter().map(|v| v.2).collect();
                let x3: Vec<f64> = sm.iter().map(|v| v.3).collect();
                let (m1, s1) = mean_std(&x1);
                let (m2, s2) = mean_std(&x2);
                if s1 > 0.0 && s2 > 0.0 {
                    let c: f64 = x1
                        .iter()
                        .zip(x2.iter())
                        .map(|(a, b)| (a - m1) * (b - m2))
                        .sum::<f64>()
                        / x1.len() as f64;
                    rho_sum += c / (s1 * s2);
                    rho_n += 1;
                }
                let (m3, s3) = mean_std(&x3);
                if s1 > 0.0 && s3 > 0.0 {
                    let c: f64 = x1
                        .iter()
                        .zip(x3.iter())
                        .map(|(a, b)| (a - m1) * (b - m3))
                        .sum::<f64>()
                        / x1.len() as f64;
                    rho13_sum += c / (s1 * s3);
                    rho13_n += 1;
                }
                if s2 > 0.0 && s3 > 0.0 {
                    let c: f64 = x2
                        .iter()
                        .zip(x3.iter())
                        .map(|(a, b)| (a - m2) * (b - m3))
                        .sum::<f64>()
                        / x2.len() as f64;
                    rho23_sum += c / (s2 * s3);
                    rho23_n += 1;
                }
                for ((a, b), c3) in x1.iter().zip(x2.iter()).zip(x3.iter()) {
                    p_n += 1.0;
                    p_sx1 += a;
                    p_sx2 += b;
                    p_sx3 += c3;
                    p_sx1q += a * a;
                    p_sx2q += b * b;
                    p_sx3q += c3 * c3;
                    p_sx1x2 += a * b;
                    p_sx1x3 += a * c3;
                    p_sx2x3 += b * c3;
                }
            }
        }
        let pooled = |sx: f64, sy: f64, sxy: f64, sxq: f64, syq: f64, n: f64| -> f64 {
            let cov = n * sxy - sx * sy;
            let vx = n * sxq - sx * sx;
            let vy = n * syq - sy * sy;
            if vx > 0.0 && vy > 0.0 { cov / (vx * vy).sqrt() } else { f64::NAN }
        };
        println!("nseeds: {nseeds} n_per_seed: {n_ev}");
        println!("rho_hat_h0: {:.4} (n={rho_n})", if rho_n > 0 { rho_sum / rho_n as f64 } else { f64::NAN });
        println!("rho_hat_h0_s1s2b: {:.4} (n={rho13_n})", if rho13_n > 0 { rho13_sum / rho13_n as f64 } else { f64::NAN });
        println!("rho_hat_h0_s2as2b: {:.4} (n={rho23_n})", if rho23_n > 0 { rho23_sum / rho23_n as f64 } else { f64::NAN });
        println!("rho_pooled_s1s2a: {:.4} (m={})", pooled(p_sx1, p_sx2, p_sx1x2, p_sx1q, p_sx2q, p_n), p_n as u64);
        println!("rho_pooled_s1s2b: {:.4} (m={})", pooled(p_sx1, p_sx3, p_sx1x3, p_sx1q, p_sx3q, p_n), p_n as u64);
        println!("rho_pooled_s2as2b: {:.4} (m={})", pooled(p_sx2, p_sx3, p_sx2x3, p_sx2q, p_sx3q, p_n), p_n as u64);
        println!("# FAR (%) per h — s1-only | s2a-only | OR");
        for (i, &h) in H_GRID.iter().enumerate() {
            let f = |x: usize| 100.0 * x as f64 / nseeds as f64;
            println!(
                "far_h{h:.0}: s1={:.2} s2a={:.2} OR={:.2}",
                f(hits[i][0]), f(hits[i][1]), f(hits[i][2])
            );
        }
        println!("# FAR (%) per h — pair variant: s2b-only | OR{{s1,s2b}} | AND{{s1,s2b}}");
        for (i, &h) in H_GRID.iter().enumerate() {
            let f = |x: usize| 100.0 * x as f64 / nseeds as f64;
            println!(
                "farsb_h{h:.0}: s2b={:.2} ORsb={:.2} ANDsb={:.2}",
                f(hits_sb[i][0]), f(hits_sb[i][1]), f(hits_sb[i][2])
            );
        }
        println!("wall_ms: {:.0}", t0.elapsed().as_secs_f64() * 1e3);
        println!("all_done");
        return;
    }

    // h0 / drift 单跑
    let events = gen_events(n, seed, drift_at, delta_rate, drift_type);
    let (sm, rate_est, cw, nw) = samples(&events, sliding);
    let alarms = run_cusums(&sm);
    let alarms_sb = run_cusums_sb(&sm);
    let x1: Vec<f64> = sm.iter().map(|v| v.1).collect();
    let x2: Vec<f64> = sm.iter().map(|v| v.2).collect();
    let x3: Vec<f64> = sm.iter().map(|v| v.3).collect();
    let (m1, sd1) = mean_std(&x1);
    let (m2, sd2) = mean_std(&x2);
    let (m3, sd3) = mean_std(&x3);
    println!("rate_est: {rate_est:.6}");
    println!("windows: calib={cw} total={nw} scored={}", sm.len());
    println!("x1_scored: mean={m1:.4} std={sd1:.4}");
    println!("x2_scored: mean={m2:.4} std={sd2:.4}");
    println!("x3_scored: mean={m3:.4} std={sd3:.4}  # s2b (priv>=2 z)");
    println!("# h grid: s1-only | s2a-only | OR(min)");
    for (i, &h) in H_GRID.iter().enumerate() {
        let or = match (alarms[i].s1, alarms[i].s2a) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        println!("alarm_h{h:.0}: s1={} s2a={} OR={}", fmt(alarms[i].s1), fmt(alarms[i].s2a), fmt(or));
    }
    println!("# h grid pair variant: s2b-only | OR{{s1,s2b}} | AND{{s1,s2b}}");
    for (i, &h) in H_GRID.iter().enumerate() {
        println!(
            "alarm_h{h:.0}_sb: s2b={} ORsb={} ANDsb={}",
            fmt(alarms_sb[i].s2b), fmt(alarms_sb[i].or_sb), fmt(alarms_sb[i].and_sb)
        );
    }
    println!("wall_ms: {:.1}", t0.elapsed().as_secs_f64() * 1e3);
    println!("all_done");
}
