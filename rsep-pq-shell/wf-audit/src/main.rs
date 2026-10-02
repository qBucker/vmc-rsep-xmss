//! Winterfell STARK 审计链演示 —— VMC/RSEP-XMSS 后量子外壳对冲轨。
//!
//! 语句（对应 V6 论文 §8 审计链）：C_t = P([C_{t-1}, B_t, DS])[0]，
//! 其中 P 为 Poseidon 置换的 Goldilocks f64 实例，T = 32 个审计块，
//! 公开输入 = (C_0, C_T)，见证 = {B_t} 与全部中间状态。
//!
//! 诚实边界（务必随数字一起引用）：
//! 1. 工程演示参数，非安全参数集：64 位 Goldilocks 域容量有限，
//!    以该域做哈希的抗碰撞界偏弱；安全参数化（如 128 位域实例）留作未来工作。
//! 2. 常量派生沿用仓库方案 Blake2b512(b"rsep-xmss-poseidon-v1" || domain || label || idx)，
//!    非规范 Grain-LFSR；MDS 矩阵为伪随机派生、未验证 MDS 性质
//!    （与 rsep-xmss BN254 实例同一边界声明）。
//! 3. S 盒指数 α = 7（Goldilocks 上 gcd(7, p-1) = 1；α = 5 不可逆因 5 | p-1），
//!    轮结构 8 全轮 + 57 部分轮镜像仓库实例。
//! 4. STARK 为哈希型证明系统，普遍认为抗量子（plausibly post-quantum）；
//!    具体安全级别以验证端 MinConjecturedSecurity 门槛为准（猜想安全，非归约证明）。

use std::time::Instant;

use blake2::{Blake2b512, Digest};
use winter_utils::Serializable;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension,
    PartitionOptions, ProofOptions, Prover, StarkDomain, Trace, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree,
};

// ---------------------------------------------------------------------------
// 参数：镜像 rsep-xmss 仓库 Poseidon 结构（rate 2 / cap 1 / t = 3 / 8+57 轮）
// ---------------------------------------------------------------------------

const STATE_WIDTH: usize = 3;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 57;
const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS; // 65
const HALF_FULL: usize = FULL_ROUNDS / 2; // 4

/// 块布局：行 0..=64 为轮次行，行 65 为输出行，行 66..=127 为 idle 行。
const BLOCK_ROWS: usize = 128;
/// 审计链块数。
const T_BLOCKS: usize = 32;
const TRACE_LEN: usize = BLOCK_ROWS * T_BLOCKS; // 4096

/// Goldilocks 模数 p = 2^64 - 2^32 + 1。
const P_MOD: u64 = 0xFFFF_FFFF_0000_0001;
/// 本演示实例的派生域（与 BN254 实例区分）。
const DOMAIN: &[u8] = b"rsep-xmss-audit-f64";

type F = BaseElement;

struct Params {
    mds: [[F; STATE_WIDTH]; STATE_WIDTH],
    rc: Vec<[F; STATE_WIDTH]>,
    ds: F,
}

fn reduce64(buf: &[u8]) -> F {
    let v = u64::from_le_bytes(buf[..8].try_into().unwrap());
    F::new(((v as u128) % (P_MOD as u128)) as u64)
}

/// 与仓库 PoseidonParams::derive 相同的标签方案（label 0x01 = MDS，0x02 = RC；
/// 0x03 = 域分离常量 DS，为本演示新增）。
fn derive_params() -> Params {
    let mut seed = [0u8; 64];
    {
        let mut h = Blake2b512::new();
        h.update(b"rsep-xmss-poseidon-v1");
        h.update(DOMAIN);
        seed.copy_from_slice(&h.finalize());
    }
    let next = |label: u8, idx: u64| -> F {
        let mut h = Blake2b512::new();
        h.update(seed);
        h.update([label]);
        h.update(idx.to_be_bytes());
        let out = h.finalize();
        reduce64(&out)
    };

    let mut mds = [[F::ZERO; STATE_WIDTH]; STATE_WIDTH];
    for (i, row) in mds.iter_mut().enumerate() {
        for (j, cell) in row.iter_mut().enumerate() {
            *cell = next(0x01, (i * STATE_WIDTH + j) as u64);
        }
    }
    let mut rc = Vec::with_capacity(TOTAL_ROUNDS);
    for r in 0..TOTAL_ROUNDS as u64 {
        let mut row = [F::ZERO; STATE_WIDTH];
        for (k, cell) in row.iter_mut().enumerate() {
            *cell = next(0x02, r * STATE_WIDTH as u64 + k as u64);
        }
        rc.push(row);
    }
    let ds = next(0x03, 0);
    Params { mds, rc, ds }
}

#[inline]
fn pow7<E: FieldElement>(x: E) -> E {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    x6 * x
}

/// 单轮：AddRoundConstants -> S 盒（x^7）-> MDS 混合。与仓库 permute 同构。
fn apply_round(p: &Params, s: &mut [F; STATE_WIDTH], r: usize) {
    for k in 0..STATE_WIDTH {
        s[k] = s[k] + p.rc[r][k];
    }
    let full = r < HALF_FULL || r >= HALF_FULL + PARTIAL_ROUNDS;
    if full {
        for x in s.iter_mut() {
            *x = pow7(*x);
        }
    } else {
        s[0] = pow7(s[0]);
    }
    let old = *s;
    for i in 0..STATE_WIDTH {
        s[i] = p.mds[i][0] * old[0] + p.mds[i][1] * old[1] + p.mds[i][2] * old[2];
    }
}

/// 参考海绵链（host 侧独立模拟，用于交叉核对迹的末值）。
fn audit_chain(p: &Params, msgs: &[F]) -> F {
    let mut c = F::ZERO;
    for &b in msgs {
        let mut s = [c, b, p.ds];
        for r in 0..TOTAL_ROUNDS {
            apply_round(p, &mut s, r);
        }
        c = s[0];
    }
    c
}

// ---------------------------------------------------------------------------
// 公开输入
// ---------------------------------------------------------------------------

pub struct PublicInputs {
    c0: F,
    ct: F,
}

impl ToElements<F> for PublicInputs {
    fn to_elements(&self) -> Vec<F> {
        vec![self.c0, self.ct]
    }
}

// ---------------------------------------------------------------------------
// AIR
// ---------------------------------------------------------------------------
//
// 周期列（周期 128，下标即 evaluate_transition 中 pv 的顺序）：
//   0..=2  P_k  ：轮常量（r < 65），其余为 0
//   3..=5  E_k  ：S 盒掩码（E0 恒 1；E1/E2 仅全轮为 1），r < 65 有效
//   6      G    ：轮约束门（r < 65）
//   7      CG0  ：s0 连续性门（65 <= r <= 127，跨块衔接 C_t）
//   8      CG1  ：s1/s2 连续性门（65 <= r <= 126；块边界放行新 B_t 与 DS）
//   9      M0   ：块首掩码（r == 0）
//   10     D    ：块首域分离常量（r == 0 处为 DS，其余为 0）

struct AuditAir {
    context: AirContext<F>,
    params: Params,
    c0: F,
    ct: F,
}

impl Air for AuditAir {
    type BaseField = F;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(STATE_WIDTH, trace_info.width());
        let degrees = vec![
            // 轮约束：u^7（迹 7 次）× 周期列 E_k、G
            TransitionConstraintDegree::with_cycles(7, vec![128, 128]),
            TransitionConstraintDegree::with_cycles(7, vec![128, 128]),
            TransitionConstraintDegree::with_cycles(7, vec![128, 128]),
            // 连续性约束：线性 × 一条周期列
            TransitionConstraintDegree::with_cycles(1, vec![128]),
            TransitionConstraintDegree::with_cycles(1, vec![128]),
            TransitionConstraintDegree::with_cycles(1, vec![128]),
            // 块首 DS 约束：M0*(s2 - D)
            TransitionConstraintDegree::with_cycles(1, vec![128, 128]),
        ];
        let context = AirContext::new(trace_info, degrees, 2, options);
        AuditAir {
            context,
            params: derive_params(),
            c0: pub_inputs.c0,
            ct: pub_inputs.ct,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();
        let pv = periodic_values;

        let u = [cur[0] + pv[0], cur[1] + pv[1], cur[2] + pv[2]];
        let e = [pv[3], pv[4], pv[5]];
        let (g, cg0, cg1, m0, d) = (pv[6], pv[7], pv[8], pv[9], pv[10]);

        // v_k = u_k + E_k * (u_k^7 - u_k)：E_k=1 时取 S 盒输出，否则直通。
        let mut v = [E::ZERO; STATE_WIDTH];
        for k in 0..STATE_WIDTH {
            v[k] = u[k] + e[k] * (pow7(u[k]) - u[k]);
        }
        for j in 0..STATE_WIDTH {
            let mut mixed = E::ZERO;
            for k in 0..STATE_WIDTH {
                mixed += E::from(self.params.mds[j][k]) * v[k];
            }
            result[j] = g * (nxt[j] - mixed);
        }

        result[3] = cg0 * (nxt[0] - cur[0]);
        result[4] = cg1 * (nxt[1] - cur[1]);
        result[5] = cg1 * (nxt[2] - cur[2]);
        result[6] = m0 * (cur[2] - d);
    }

    fn get_assertions(&self) -> Vec<Assertion<F>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.c0),
            Assertion::single(0, last_step, self.ct),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<F>> {
        let mut cols = vec![vec![F::ZERO; BLOCK_ROWS]; 11];
        for r in 0..TOTAL_ROUNDS {
            cols[0][r] = self.params.rc[r][0];
            cols[1][r] = self.params.rc[r][1];
            cols[2][r] = self.params.rc[r][2];
            cols[3][r] = F::ONE; // E0：每轮 S 盒作用于 s0
            if r < HALF_FULL || r >= HALF_FULL + PARTIAL_ROUNDS {
                cols[4][r] = F::ONE;
                cols[5][r] = F::ONE;
            }
            cols[6][r] = F::ONE; // G
        }
        for r in 65..BLOCK_ROWS {
            cols[7][r] = F::ONE; // CG0：含 r = 127（跨块 s0 衔接）
        }
        for r in 65..(BLOCK_ROWS - 1) {
            cols[8][r] = F::ONE; // CG1：止于 r = 126
        }
        cols[9][0] = F::ONE; // M0
        cols[10][0] = self.params.ds; // D
        cols
    }

    fn context(&self) -> &AirContext<F> {
        &self.context
    }
}

// ---------------------------------------------------------------------------
// Prover（按 winterfell 0.13 文档样板）
// ---------------------------------------------------------------------------

struct AuditProver {
    options: ProofOptions,
}

impl AuditProver {
    fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for AuditProver {
    type BaseField = F;
    type Air = AuditAir;
    type Trace = TraceTable<F>;
    type HashFn = Blake3_256<F>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        PublicInputs {
            c0: trace.get(0, 0),
            ct: trace.get(0, last_step),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

// ---------------------------------------------------------------------------
// 主流程：构迹 -> 交叉核对 -> 证明 -> 验证 -> 输出
// ---------------------------------------------------------------------------

fn main() {
    println!("=== Winterfell STARK 审计链演示（工程演示参数，非安全参数集）===");
    println!("语句: C_t = P([C_{{t-1}}, B_t, DS])[0], T = {T_BLOCKS} 块, Poseidon-f64 (t=3, a=7, 8+57 轮)");
    println!("迹: {STATE_WIDTH} 列 x {TRACE_LEN} 行（块 {BLOCK_ROWS} 行 = 65 轮 + 输出行 + idle）");

    let params = derive_params();
    // 演示审计消息：确定性可复现
    let msgs: Vec<F> = (0..T_BLOCKS)
        .map(|t| F::new(0xA0D1_7000u64 + t as u64))
        .collect();

    // --- 构迹 ---
    let t_trace = Instant::now();
    let mut trace = TraceTable::new(STATE_WIDTH, TRACE_LEN);
    {
        let params_ref = &params;
        let msgs_ref = &msgs;
        trace.fill(
            |state| {
                state[0] = F::ZERO; // C_0
                state[1] = msgs_ref[0]; // B_0
                state[2] = params_ref.ds;
            },
            |i, state| {
                let r = i % BLOCK_ROWS;
                if r < TOTAL_ROUNDS {
                    let s: &mut [F; STATE_WIDTH] = state.try_into().unwrap();
                    apply_round(params_ref, s, r);
                } else if r == BLOCK_ROWS - 1 {
                    // 块边界：s0 由 CG0 约束衔接；s1 注入新消息，s2 复位 DS
                    state[1] = msgs_ref[i / BLOCK_ROWS + 1];
                    state[2] = params_ref.ds;
                }
                // 65..=126：idle，原样拷贝（CG0/CG1 约束）
            },
        );
    }
    let trace_ms = t_trace.elapsed().as_secs_f64() * 1e3;

    // --- 交叉核对 ---
    let expect_ct = audit_chain(&params, &msgs);
    let ct = trace.get(0, TRACE_LEN - 1);
    assert_eq!(expect_ct, ct, "迹末值与参考链不一致（迹构造有 bug）");
    println!("C_0 = 0x{:016x}", u64::from(F::ZERO));
    println!("C_T = 0x{:016x} (trace {:.3} ms)", u64::from(ct), trace_ms);

    // --- 证明 ---
    let options = ProofOptions::new(
        42,                       // queries
        8,                        // blowup（约束最小需求 = 8）
        16,                       // grinding
        FieldExtension::Quadratic,
        4,                        // FRI folding
        63,                       // FRI remainder max degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let prover = AuditProver::new(options);
    let t_prove = Instant::now();
    let proof = prover.prove(trace).expect("proving failed");
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1e3;

    let proof_bytes = proof.to_bytes();
    let proof_len = proof_bytes.len();

    // --- 验证（猜想安全门槛 95 bit）---
    let min_opts = AcceptableOptions::MinConjecturedSecurity(95);
    let pub_inputs = PublicInputs { c0: F::ZERO, ct };
    let t_verify = Instant::now();
    winterfell::verify::<
        AuditAir,
        Blake3_256<F>,
        DefaultRandomCoin<Blake3_256<F>>,
        MerkleTree<Blake3_256<F>>,
    >(proof, pub_inputs, &min_opts)
    .expect("verification failed (or conjectured security < 95 bits)");
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1e3;

    println!("--- 实测（2 核沙盒） ---");
    println!("prove   : {:.1} ms", prove_ms);
    println!("verify  : {:.3} ms", verify_ms);
    println!("proof   : {} bytes ({:.1} KiB)", proof_len, proof_len as f64 / 1024.0);
    println!("verifier: MinConjecturedSecurity(95) 通过");

    std::fs::create_dir_all("out").unwrap();
    std::fs::write("out/wf-audit-proof.bin", &proof_bytes).unwrap();
    let summary = format!(
        "Winterfell STARK audit-chain demo (engineering parameters, not a secure parameter set)\n\
         statement: C_t = P([C_{{t-1}}, B_t, DS])[0], T = {T_BLOCKS} blocks, Poseidon-f64 (t=3, alpha=7, 8F+57P)\n\
         trace: {STATE_WIDTH} cols x {TRACE_LEN} rows; constraints: 7 (deg 7 base, cycles [128,128]); blowup 8\n\
         options: 42 queries, grinding 16, quadratic extension, FRI fold 4, remainder 63, Linear batching\n\
         C_T = 0x{:016x}\n\
         trace_build_ms = {trace_ms:.3}\n\
         prove_ms = {prove_ms:.1}\n\
         verify_ms = {verify_ms:.3}\n\
         proof_bytes = {proof_len}\n\
         verifier_gate = MinConjecturedSecurity(95) PASS\n",
        u64::from(ct)
    );
    std::fs::write("out/wf-bench.txt", summary).unwrap();
    println!("输出: out/wf-audit-proof.bin, out/wf-bench.txt");
}
