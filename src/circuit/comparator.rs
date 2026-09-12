//! 严格序比较器 `C_≺(v_old, v_new)`。
//!
//! 与论文 §4.2 与附录 A 一致。主体 3 条乘法约束：
//!
//! ```text
//! w1  = (1 - x0) · y0
//! w2  = y1 + w1 - y1 · w1     ⇔  y1 · w1 = y1 + w1 - w2
//! out = (1 - x1) · w2
//! ```
//!
//! 4 条 booleanity 引脚（`x1, x0, y1, y0 ∈ {0,1}`）**不在**本模块内
//! 计账，由调用方（[`crate::circuit::rsep`]）施加并计入。

use crate::Fr;
use ark_relations::r1cs::{
    ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

/// 比较器主体约束数（不含 booleanity 引脚）。
pub const COMPARATOR_BODY_CONSTRAINTS: usize = 3;

/// 严格序比较器 gadget。
pub struct StrictOrderGadget;

impl StrictOrderGadget {
    /// 施加 `C_≺(x, y)` 的 3 条乘法约束，返回 `(输出变量, 输出值)`。
    ///
    /// 每个输入位以 `(Variable, host-side value)` 传入——`Variable`
    /// 本身无法取值（审计第十五轮修复：原实现调用不存在的
    /// `Variable::value()`）。
    ///
    /// 调用方**必须**先对 `x1, x0, y1, y0` 施加 booleanity 约束
    /// （4 条），或确保它们来自已约束为布尔值的源。
    pub fn enforce(
        cs: &ConstraintSystemRef<Fr>,
        x1: (Variable, Fr),
        x0: (Variable, Fr),
        y1: (Variable, Fr),
        y0: (Variable, Fr),
    ) -> Result<(Variable, Fr), SynthesisError> {
        let one_minus = |v: Variable| -> LinearCombination<Fr> {
            LinearCombination(vec![
                (Fr::from(1u64), Variable::One),
                (-Fr::from(1u64), v),
            ])
        };
        let (x1, x1_val) = x1;
        let (x0, x0_val) = x0;
        let (y1, y1_val) = y1;
        let (y0, y0_val) = y0;

        // 约束 1：w1 = (1 - x0) · y0
        let w1_val = (Fr::from(1u64) - x0_val) * y0_val;
        let w1 = cs.new_witness_variable(|| Ok(w1_val))?;
        cs.enforce_constraint(
            one_minus(x0),
            LinearCombination(vec![(Fr::from(1u64), y0)]),
            LinearCombination(vec![(Fr::from(1u64), w1)]),
        )?;

        // 约束 2：y1 · w1 = y1 + w1 - w2
        let w2_val = y1_val + w1_val - y1_val * w1_val;
        let w2 = cs.new_witness_variable(|| Ok(w2_val))?;
        let mut rhs = LinearCombination(vec![
            (Fr::from(1u64), y1),
            (Fr::from(1u64), w1),
        ]);
        rhs.push((-Fr::from(1u64), w2));
        cs.enforce_constraint(
            LinearCombination(vec![(Fr::from(1u64), y1)]),
            LinearCombination(vec![(Fr::from(1u64), w1)]),
            rhs,
        )?;

        // 约束 3：out = (1 - x1) · w2
        let out_val = (Fr::from(1u64) - x1_val) * w2_val;
        let out = cs.new_witness_variable(|| Ok(out_val))?;
        cs.enforce_constraint(
            one_minus(x1),
            LinearCombination(vec![(Fr::from(1u64), w2)]),
            LinearCombination(vec![(Fr::from(1u64), out)]),
        )?;

        Ok((out, out_val))
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::LeafState;
    use ark_relations::r1cs::ConstraintSystem;

    /// 九对枚举：真值表与论文附录 A 一致。
    #[test]
    fn truth_table_matches_paper() {
        let states = [LeafState::Fresh, LeafState::Used, LeafState::Spent];
        for &xv in &states {
            for &yv in &states {
                let expected = LeafState::strict_lt_circuit(xv, yv);

                let cs = ConstraintSystem::<Fr>::new_ref();
                let (x1, x0) = xv.bits();
                let (y1, y0) = yv.bits();
                let vx1 = cs.new_witness_variable(|| Ok(Fr::from(x1))).unwrap();
                let vx0 = cs.new_witness_variable(|| Ok(Fr::from(x0))).unwrap();
                let vy1 = cs.new_witness_variable(|| Ok(Fr::from(y1))).unwrap();
                let vy0 = cs.new_witness_variable(|| Ok(Fr::from(y0))).unwrap();

                // booleanity（4 条，调用方职责；此处计入以复用真值表）
                for v in [vx1, vx0, vy1, vy0] {
                    cs.enforce_constraint(
                        LinearCombination(vec![(Fr::from(1u64), v)]),
                        LinearCombination(vec![(Fr::from(1u64), v)]),
                        LinearCombination(vec![(Fr::from(1u64), v)]),
                    )
                    .unwrap();
                }

                let (_out, out_val) = StrictOrderGadget::enforce(
                    &cs,
                    (vx1, Fr::from(x1)),
                    (vx0, Fr::from(x0)),
                    (vy1, Fr::from(y1)),
                    (vy0, Fr::from(y0)),
                )
                .unwrap();
                let got = out_val == Fr::from(1u64);
                assert_eq!(
                    got, expected,
                    "C_≺({:?}, {:?}) mismatch",
                    xv, yv
                );
                assert!(cs.is_satisfied().unwrap());
            }
        }
    }

    /// 比较器主体恰好 3 条乘法约束。
    #[test]
    fn comparator_body_is_three_constraints() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let x1 = cs.new_witness_variable(|| Ok(Fr::from(0u64))).unwrap();
        let x0 = cs.new_witness_variable(|| Ok(Fr::from(0u64))).unwrap();
        let y1 = cs.new_witness_variable(|| Ok(Fr::from(0u64))).unwrap();
        let y0 = cs.new_witness_variable(|| Ok(Fr::from(1u64))).unwrap();
        let _ = StrictOrderGadget::enforce(
            &cs,
            (x1, Fr::from(0u64)),
            (x0, Fr::from(0u64)),
            (y1, Fr::from(0u64)),
            (y0, Fr::from(1u64)),
        )
        .unwrap();
        assert_eq!(cs.num_constraints(), COMPARATOR_BODY_CONSTRAINTS);
    }
}
