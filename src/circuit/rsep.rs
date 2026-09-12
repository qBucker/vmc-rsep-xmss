//! 完整 `C_RSEP` 关系。
//!
//! 公开输入（恰好 5 个，与论文 §4.2 一致）：
//! `rho_old, rho_new, leaf_index, c_old, c_new`
//!
//! 见证：
//! * `auth_path[0..h]`：单条共享认证路径
//! * `v_old, v_new`：旧 / 新叶子状态编码
//! * 索引位：由 `leaf_index` 分解，见证内

use crate::circuit::comparator::StrictOrderGadget;
use crate::circuit::merkle_gadget::MerklePathGadget;
use crate::circuit::poseidon_gadget::PoseidonConfig;
use crate::state::LeafState;
use crate::Fr;
use ark_ff::PrimeField;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination,
    SynthesisError, Variable,
};

/// RSEP 关系电路。
#[derive(Clone)]
pub struct RsepCircuit {
    /// Poseidon 参数。
    pub poseidon: PoseidonConfig,
    /// 树高。
    pub h: usize,
    /// `true` 表示终结关系（USED → SPENT），`false` 表示签名
    /// 关系（FRESH → USED）。
    pub finalize: bool,
    /// 公开输入：旧状态根。
    pub rho_old: Fr,
    /// 公开输入：新状态根。
    pub rho_new: Fr,
    /// 公开输入：叶子索引。
    pub leaf_index: u64,
    /// 公开输入：旧计数器。
    pub c_old: u64,
    /// 公开输入：新计数器。
    pub c_new: u64,
    /// 见证：共享认证路径。
    pub auth_path: Vec<Fr>,
    /// 见证：旧叶子状态编码（0/1/2）。
    pub v_old: Fr,
    /// 见证：新叶子状态编码（0/1/2）。
    pub v_new: Fr,
}

impl RsepCircuit {
    /// 位分解约束：`sum 2^i · bit_i = value`，并施加每位
    /// booleanity（`h + 1` 条）。
    fn enforce_bit_decomposition(
        cs: &ConstraintSystemRef<Fr>,
        value: Variable,
        bits: &[Variable],
    ) -> Result<(), SynthesisError> {
        for b in bits {
            cs.enforce_constraint(
                LinearCombination(vec![(Fr::from(1u64), *b)]),
                LinearCombination(vec![(Fr::from(1u64), *b)]),
                LinearCombination(vec![(Fr::from(1u64), *b)]),
            )?;
        }
        let mut sum = LinearCombination(Vec::new());
        let mut pow = Fr::from(1u64);
        for b in bits {
            sum.push((pow, *b));
            pow = pow + pow;
        }
        sum.push((-Fr::from(1u64), value));
        cs.enforce_constraint(
            sum,
            LinearCombination(vec![(Fr::from(1u64), Variable::One)]),
            LinearCombination(vec![]),
        )?;
        Ok(())
    }

    /// 两位编码分解：`value = 2·b1 + b0`，并对 `b1, b0`
    /// 施加 booleanity（3 条）。
    fn enforce_two_bit(
        cs: &ConstraintSystemRef<Fr>,
        value: Variable,
        b1: Variable,
        b0: Variable,
    ) -> Result<(), SynthesisError> {
        for b in [b1, b0] {
            cs.enforce_constraint(
                LinearCombination(vec![(Fr::from(1u64), b)]),
                LinearCombination(vec![(Fr::from(1u64), b)]),
                LinearCombination(vec![(Fr::from(1u64), b)]),
            )?;
        }
        let sum = LinearCombination(vec![
            (Fr::from(2u64), b1),
            (Fr::from(1u64), b0),
            (-Fr::from(1u64), value),
        ]);
        cs.enforce_constraint(
            sum,
            LinearCombination(vec![(Fr::from(1u64), Variable::One)]),
            LinearCombination(vec![]),
        )?;
        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for RsepCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        // 公开输入（5 个，与论文 §4.2 一致）
        let rho_old =
            cs.new_input_variable(|| Ok(self.rho_old))?;
        let rho_new =
            cs.new_input_variable(|| Ok(self.rho_new))?;
        let leaf_index =
            cs.new_input_variable(|| Ok(Fr::from(self.leaf_index)))?;
        let c_old =
            cs.new_input_variable(|| Ok(Fr::from(self.c_old)))?;
        let c_new =
            cs.new_input_variable(|| Ok(Fr::from(self.c_new)))?;

        // 见证：索引位（h 位）并施加 h + 1 条分解约束
        let index_bits: Vec<(Variable, u64)> = (0..self.h)
            .map(|i| {
                let b = (self.leaf_index >> i) & 1;
                let v =
                    cs.new_witness_variable(|| Ok(Fr::from(b)))?;
                Ok((v, b))
            })
            .collect::<Result<_, SynthesisError>>()?;
        {
            let bits_only: Vec<Variable> =
                index_bits.iter().map(|(v, _)| *v).collect();
            Self::enforce_bit_decomposition(
                &cs,
                leaf_index,
                &bits_only,
            )?;
        }

        // 见证：路径
        let path: Vec<(Variable, Fr)> = self
            .auth_path
            .iter()
            .map(|v| {
                let var = cs.new_witness_variable(|| Ok(*v))?;
                Ok((var, *v))
            })
            .collect::<Result<_, SynthesisError>>()?;

        // 见证：叶子状态
        let v_old =
            cs.new_witness_variable(|| Ok(self.v_old))?;
        let v_new =
            cs.new_witness_variable(|| Ok(self.v_new))?;

        // v_old / v_new 的 2 位分解（各 3 条）
        let vo1_val = (self.v_old.into_bigint().0[0] >> 1) & 1;
        let vo0_val = self.v_old.into_bigint().0[0] & 1;
        let vn1_val = (self.v_new.into_bigint().0[0] >> 1) & 1;
        let vn0_val = self.v_new.into_bigint().0[0] & 1;
        let vo1 =
            cs.new_witness_variable(|| Ok(Fr::from(vo1_val)))?;
        let vo0 =
            cs.new_witness_variable(|| Ok(Fr::from(vo0_val)))?;
        let vn1 =
            cs.new_witness_variable(|| Ok(Fr::from(vn1_val)))?;
        let vn0 =
            cs.new_witness_variable(|| Ok(Fr::from(vn0_val)))?;
        Self::enforce_two_bit(&cs, v_old, vo1, vo0)?;
        Self::enforce_two_bit(&cs, v_new, vn1, vn0)?;

        // 约束 1：Merkle 验证 ρ_old ← (path, index_bits, v_old)
        let merkle = MerklePathGadget::new(self.poseidon.clone());
        merkle.verify(&cs, rho_old, v_old, self.v_old,
                      &index_bits, &path)?;

        // 约束 2：Merkle 验证 ρ_new ← (path, index_bits, v_new)
        merkle.verify(&cs, rho_new, v_new, self.v_new,
                      &index_bits, &path)?;

        // 约束 3：C_≺(v_old, v_new)，并约束结果为 1
        let (cmp, _cmp_val) = StrictOrderGadget::enforce(
            &cs,
            (vo1, Fr::from(vo1_val)),
            (vo0, Fr::from(vo0_val)),
            (vn1, Fr::from(vn1_val)),
            (vn0, Fr::from(vn0_val)),
        )?;
        cs.enforce_constraint(
            LinearCombination(vec![(Fr::from(1u64), cmp)]),
            LinearCombination(vec![(Fr::from(1u64), Variable::One)]),
            LinearCombination(vec![(Fr::from(1u64), Variable::One)]),
        )?;

        // 约束 4-5：常量检查
        let (exp_old, exp_new) = if self.finalize {
            (LeafState::Used.to_fr(), LeafState::Spent.to_fr())
        } else {
            (LeafState::Fresh.to_fr(), LeafState::Used.to_fr())
        };
        cs.enforce_constraint(
            LinearCombination(vec![(Fr::from(1u64), v_old)]),
            LinearCombination(vec![(Fr::from(1u64), Variable::One)]),
            LinearCombination(vec![(exp_old, Variable::One)]),
        )?;
        cs.enforce_constraint(
            LinearCombination(vec![(Fr::from(1u64), v_new)]),
            LinearCombination(vec![(Fr::from(1u64), Variable::One)]),
            LinearCombination(vec![(exp_new, Variable::One)]),
        )?;

        // 约束 6：c_new - c_old - 1 = 0
        let diff = LinearCombination(vec![
            (Fr::from(1u64), c_new),
            (-Fr::from(1u64), c_old),
        ]);
        cs.enforce_constraint(
            diff,
            LinearCombination(vec![(Fr::from(1u64), Variable::One)]),
            LinearCombination(vec![(Fr::from(1u64), Variable::One)]),
        )?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::PoseidonParams;
    use ark_relations::r1cs::ConstraintSystem;

    /// 构造一棵小的状态树与给定叶子的路径。
    fn setup(h: usize) -> (PoseidonParams, Vec<Vec<Fr>>) {
        let p = PoseidonParams::derive(b"rsep-circuit-tests");
        let n = 1usize << h;
        let leaves: Vec<Fr> = (0..n).map(|_| Fr::from(0u64)).collect();
        let mut layers = vec![leaves.clone()];
        let mut cur = leaves;
        while cur.len() > 1 {
            let mut next = vec![];
            for pair in cur.chunks(2) {
                next.push(p.hash2(pair[0], pair[1]));
            }
            layers.push(next.clone());
            cur = next;
        }
        (p, layers)
    }

    fn path_at(layers: &[Vec<Fr>], h: usize, idx: usize) -> Vec<Fr> {
        let mut path = vec![];
        let mut i = idx;
        for level in 0..h {
            path.push(layers[level][i ^ 1]);
            i >>= 1;
        }
        path
    }

    #[test]
    fn signature_relation_is_satisfied() {
        let h = 3usize;
        let (p, layers) = setup(h);
        let cfg = PoseidonConfig::new(&p);

        // 在位置 2 上把叶子从 Fresh(0) 改为 Used(1)
        let idx = 2usize;
        let old_leaf = Fr::from(0u64);
        let new_leaf = Fr::from(1u64);

        let old_root = *layers.last().unwrap().last().unwrap();

        // 计算新根：重建树
        let n = 1usize << h;
        let mut leaves: Vec<Fr> = (0..n).map(|_| Fr::from(0u64)).collect();
        leaves[idx] = new_leaf;
        let mut cur = leaves;
        while cur.len() > 1 {
            let mut next = vec![];
            for pair in cur.chunks(2) {
                next.push(p.hash2(pair[0], pair[1]));
            }
            cur = next;
        }
        let new_root = cur[0];

        let path = path_at(&layers, h, idx);

        let circuit = RsepCircuit {
            poseidon: cfg,
            h,
            finalize: false,
            rho_old: old_root,
            rho_new: new_root,
            leaf_index: idx as u64,
            c_old: 0,
            c_new: 1,
            auth_path: path,
            v_old: old_leaf,
            v_new: new_leaf,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn constraint_count_at_h10() {
        let h = 10usize;
        let (p, _) = setup(h);
        let cfg = PoseidonConfig::new(&p);
        let circuit = RsepCircuit {
            poseidon: cfg,
            h,
            finalize: false,
            rho_old: Fr::from(0u64),
            rho_new: Fr::from(0u64),
            leaf_index: 0,
            c_old: 0,
            c_new: 1,
            auth_path: vec![Fr::from(0u64); h],
            v_old: Fr::from(0u64),
            v_new: Fr::from(1u64),
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        let n = cs.num_constraints();
        // 口径：2h × 276 (Poseidon hash2_lc：243 条 S-box 乘法
        //              + 33 条 LC 折叠开销——第四波实测发现部分轮
        //              线性组合指数膨胀，超阈值折叠回 witness，
        //              每次 +3，结构性确定共 11 次)
        //       + 2 (root 绑定)
        //       + h + 1 (index 位)
        //       + 6 (v_old / v_new 位分解)
        //       + 3 + 1 (比较器 + 结果绑定)
        //       + 2 (常量检查) + 1 (计数器)
        //       + 4h (Merkle 方向 mux：每级 2 条 × 双路径，F2 修复)
        //       = 2h × 276 + 5h + 16
        let expected = 2 * h * 276 + 5 * h + 16;
        assert_eq!(n, expected, "got {}, expected {}", n, expected);
        // 对照论文 §6 Table 2（按 300 条/hash2 上界估值 ~6,041）；
        // 单次 hash2 实测 276–277 条，仍落在论文 §6 正文所述
        // 240–300 区间内，且总量低于 Table 2 上界估值。
        eprintln!(
            "RsepCircuit h={} constraints = {} (paper §6 Table 2 upper-bound ≈ 6,041)",
            h, n
        );
    }

    #[test]
    fn finalization_relation_is_satisfied() {
        let h = 2usize;
        let (p, _) = setup(h);
        let cfg = PoseidonConfig::new(&p);

        let idx = 1usize;
        // 构造初始树：位置 1 已为 Used(1)
        let n = 1usize << h;
        let mut leaves: Vec<Fr> = (0..n).map(|_| Fr::from(0u64)).collect();
        leaves[idx] = Fr::from(1u64);
        let mut layers_used = vec![leaves.clone()];
        let mut cur = leaves.clone();
        while cur.len() > 1 {
            let mut next = vec![];
            for pair in cur.chunks(2) {
                next.push(p.hash2(pair[0], pair[1]));
            }
            layers_used.push(next.clone());
            cur = next;
        }
        let old_root = *layers_used.last().unwrap().last().unwrap();
        let path = path_at(&layers_used, h, idx);

        // 终结：Used(1) → Spent(2)
        leaves[idx] = Fr::from(2u64);
        let mut cur = leaves;
        while cur.len() > 1 {
            let mut next = vec![];
            for pair in cur.chunks(2) {
                next.push(p.hash2(pair[0], pair[1]));
            }
            cur = next;
        }
        let new_root = cur[0];

        let circuit = RsepCircuit {
            poseidon: cfg,
            h,
            finalize: true,
            rho_old: old_root,
            rho_new: new_root,
            leaf_index: idx as u64,
            c_old: 5,
            c_new: 6,
            auth_path: path,
            v_old: Fr::from(1u64),
            v_new: Fr::from(2u64),
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
