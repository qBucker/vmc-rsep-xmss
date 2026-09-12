//! Merkle 认证路径的电路 gadget。
//!
//! 与域外 [`crate::poseidon::PoseidonParams::hash2`] 语义一致
//! （plain hash2，无 ADRS、无掩码）。
//!
//! ## 方向选择
//!
//! 论文 §4.2 的共享路径 `P` 在所有层级都是同一组兄弟节点；方向
//! 由 `leaf_index` 的位决定。本 gadget 用见证变量 `index_bits`
//! 表示索引位，**要求调用方**（[`crate::circuit::rsep`]）已施加
//! booleanity 与位分解约束。本 gadget 内不再重复施加。

use crate::circuit::poseidon_gadget::PoseidonConfig;
use crate::Fr;
use ark_relations::r1cs::{
    ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

/// Merkle 路径验证 gadget。
pub struct MerklePathGadget {
    config: PoseidonConfig,
}

impl MerklePathGadget {
    /// 构造。
    pub fn new(config: PoseidonConfig) -> Self {
        MerklePathGadget { config }
    }

    /// 计算叶子沿认证路径上升后的根。
    ///
    /// 输入：
    /// * `leaf_lc`：叶子值的 LC
    /// * `leaf_val`：叶子值的 host-side 值
    /// * `index_bits`：`(Variable, value)` 序列，从 LSB 到 MSB
    /// * `path`：`(Variable, value)` 序列，同序
    ///
    /// 输出：`(root_lc, root_val)`。调用方通常把它与公开的
    /// `rho` 用一条线性约束绑定。
    pub fn compute_root(
        &self,
        cs: &ConstraintSystemRef<Fr>,
        leaf_lc: LinearCombination<Fr>,
        leaf_val: Fr,
        index_bits: &[(Variable, u64)],
        path: &[(Variable, Fr)],
    ) -> Result<(LinearCombination<Fr>, Fr), SynthesisError> {
        assert_eq!(index_bits.len(), path.len());
        let mut cur_lc = leaf_lc;
        let mut cur_val = leaf_val;

        for level in 0..path.len() {
            let (bit_var, bit_val) = index_bits[level];
            let (sib_var, sib_val) = path[level];

            // 方向选择在电路内多路复用（修复 F2）：
            //   bit = 0 → left = cur, right = sib
            //   bit = 1 → left = sib, right = cur
            //
            //   diff    = sib − cur            （线性，免费）
            //   t_left  = bit · diff           （1 条乘法门）
            //   t_right = (1 − bit) · diff     （1 条乘法门）
            //   left  = cur + t_left           （线性，免费）
            //   right = cur + t_right          （线性，免费）
            //
            // 约束矩阵的接线对任意 leaf_index 一致；host 侧
            // bit_val 只用于生成 witness 值，不再决定矩阵结构。
            let mut diff_lc: LinearCombination<Fr> =
                LinearCombination(vec![(Fr::from(1u64), sib_var)]);
            for (c, v) in &cur_lc.0 {
                diff_lc.push((-*c, *v));
            }
            let diff_val = sib_val - cur_val;

            let t_left_val = Fr::from(bit_val) * diff_val;
            let t_left = cs.new_witness_variable(|| Ok(t_left_val))?;
            cs.enforce_constraint(
                LinearCombination(vec![(Fr::from(1u64), bit_var)]),
                diff_lc.clone(),
                LinearCombination(vec![(Fr::from(1u64), t_left)]),
            )?;

            let t_right_val =
                (Fr::from(1u64) - Fr::from(bit_val)) * diff_val;
            let t_right = cs.new_witness_variable(|| Ok(t_right_val))?;
            let one_minus_bit_lc = LinearCombination(vec![
                (Fr::from(1u64), Variable::One),
                (-Fr::from(1u64), bit_var),
            ]);
            cs.enforce_constraint(
                one_minus_bit_lc,
                diff_lc,
                LinearCombination(vec![(Fr::from(1u64), t_right)]),
            )?;

            let mut left_lc = cur_lc.clone();
            left_lc.push((Fr::from(1u64), t_left));
            let left_val = cur_val + t_left_val;

            let mut right_lc = cur_lc.clone();
            right_lc.push((Fr::from(1u64), t_right));
            let right_val = cur_val + t_right_val;

            let (next_lc, next_val) = self.config.hash2_lc(
                cs,
                left_lc,
                left_val,
                right_lc,
                right_val,
            )?;
            cur_lc = next_lc;
            cur_val = next_val;
        }
        Ok((cur_lc, cur_val))
    }

    /// 验证路径得到预期根。
    ///
    /// 施加：`compute_root(leaf, index_bits, path) = root`（1 条）。
    pub fn verify(
        &self,
        cs: &ConstraintSystemRef<Fr>,
        root: Variable,
        leaf: Variable,
        leaf_val: Fr,
        index_bits: &[(Variable, u64)],
        path: &[(Variable, Fr)],
    ) -> Result<(), SynthesisError> {
        let (root_lc, _root_val) = self.compute_root(
            cs,
            LinearCombination(vec![(Fr::from(1u64), leaf)]),
            leaf_val,
            index_bits,
            path,
        )?;
        let mut diff = root_lc;
        diff.push((-Fr::from(1u64), root));
        cs.enforce_constraint(
            diff,
            LinearCombination(vec![(Fr::from(1u64), Variable::One)]),
            LinearCombination(vec![]),
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
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};

    fn params() -> PoseidonParams {
        PoseidonParams::derive(b"merkle-gadget-tests")
    }

    /// 小规模 Merkle 树 + 电路路径验证。
    struct MerkleVerifyCircuit {
        config: PoseidonConfig,
        root: Fr,
        leaf: Fr,
        leaf_index: usize,
        path: Vec<Fr>,
        h: usize,
    }

    impl ConstraintSynthesizer<Fr> for MerkleVerifyCircuit {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<Fr>,
        ) -> Result<(), SynthesisError> {
            let root = cs.new_input_variable(|| Ok(self.root))?;
            let leaf = cs.new_witness_variable(|| Ok(self.leaf))?;
            let index_bits: Vec<(Variable, u64)> = (0..self.h)
                .map(|i| {
                    let b = ((self.leaf_index >> i) & 1) as u64;
                    let v = cs.new_witness_variable(|| Ok(Fr::from(b)))?;
                    cs.enforce_constraint(
                        LinearCombination(vec![(Fr::from(1u64), v)]),
                        LinearCombination(vec![(Fr::from(1u64), v)]),
                        LinearCombination(vec![(Fr::from(1u64), v)]),
                    )
                    .unwrap();
                    Ok((v, b))
                })
                .collect::<Result<_, SynthesisError>>()?;
            let path: Vec<(Variable, Fr)> = self
                .path
                .iter()
                .map(|v| {
                    let var = cs.new_witness_variable(|| Ok(*v))?;
                    Ok((var, *v))
                })
                .collect::<Result<_, SynthesisError>>()?;

            let gadget = MerklePathGadget::new(self.config);
            gadget.verify(&cs, root, leaf, self.leaf, &index_bits, &path)?;
            Ok(())
        }
    }

    #[test]
    fn verify_valid_path() {
        let p = params();
        let c = PoseidonConfig::new(&p);
        let h = 3usize;
        let leaves: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64 + 1)).collect();

        // 手动构建树
        let mut layers = vec![leaves.clone()];
        let mut cur = leaves.clone();
        while cur.len() > 1 {
            let mut next = vec![];
            for pair in cur.chunks(2) {
                next.push(p.hash2(pair[0], pair[1]));
            }
            layers.push(next.clone());
            cur = next;
        }
        let root = *layers.last().unwrap().last().unwrap();

        for idx in 0..8usize {
            let mut path = vec![];
            let mut i = idx;
            for level in 0..h {
                path.push(layers[level][i ^ 1]);
                i >>= 1;
            }
            let circuit = MerkleVerifyCircuit {
                config: c.clone(),
                root,
                leaf: leaves[idx],
                leaf_index: idx,
                path,
                h,
            };
            let cs = ConstraintSystem::<Fr>::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(cs.is_satisfied().unwrap(), "index {} failed", idx);
        }
    }

    /// F2 的真回归测试（审计第十五轮裁定：约束数比较不具判别力——
    /// 旧代码的约束条数同样与 index 无关，只有矩阵内容不同）。
    ///
    /// 判别方式与生产路径一致：setup 用 index 0 模板（对应
    /// `proof::setup` 的 `leaf_index: 0` 模板），再对 index 1..8
    /// 逐一 prove + verify。修复前：index≥1 的 QAP 与 setup 的
    /// CRS 不一致，verify 必为 false；修复后：全部通过。
    #[test]
    fn setup_at_index_0_prove_at_all_indices() {
        use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

        let p = params();
        let c = PoseidonConfig::new(&p);
        let h = 3usize;
        let leaves: Vec<Fr> =
            (0..8).map(|i| Fr::from(i as u64 + 1)).collect();
        let mut layers = vec![leaves.clone()];
        let mut cur = leaves.clone();
        while cur.len() > 1 {
            let mut next = vec![];
            for pair in cur.chunks(2) {
                next.push(p.hash2(pair[0], pair[1]));
            }
            layers.push(next.clone());
            cur = next;
        }
        let root = *layers.last().unwrap().last().unwrap();
        let path_for = |idx: usize| {
            let mut path = vec![];
            let mut i = idx;
            for level in 0..h {
                path.push(layers[level][i ^ 1]);
                i >>= 1;
            }
            path
        };

        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let template = MerkleVerifyCircuit {
            config: c.clone(),
            root,
            leaf: leaves[0],
            leaf_index: 0,
            path: path_for(0),
            h,
        };
        let pk = Groth16::<ark_bn254::Bn254, LibsnarkReduction>
            ::generate_random_parameters_with_reduction(template, &mut rng)
            .unwrap();
        let pvk = pk.vk.clone().into();

        for idx in 1..8usize {
            let circuit = MerkleVerifyCircuit {
                config: c.clone(),
                root,
                leaf: leaves[idx],
                leaf_index: idx,
                path: path_for(idx),
                h,
            };
            let proof = Groth16::<ark_bn254::Bn254, LibsnarkReduction>
                ::create_random_proof_with_reduction(circuit, &pk, &mut rng)
                .unwrap();
            let ok = Groth16::<ark_bn254::Bn254, LibsnarkReduction>
                ::verify_proof(&pvk, &proof, &[root])
                .unwrap();
            assert!(ok, "index {} failed against index-0 setup", idx);
        }
    }
}
