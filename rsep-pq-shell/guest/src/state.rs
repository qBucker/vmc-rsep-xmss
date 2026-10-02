//! 三元素状态链 `FRESH ≺ USED ≺ SPENT`。

use ark_bn254::Fr;
use ark_ff::PrimeField;

/// 叶子状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LeafState {
    /// 未使用，WOTS+ 私钥完整。
    Fresh,
    /// 已签名，等待终结。
    Used,
    /// 已确认终结。
    Spent,
}

impl LeafState {
    /// 编码为域元素：`Fresh = 0`，`Used = 1`，`Spent = 2`。
    #[inline]
    pub fn to_fr(self) -> Fr {
        match self {
            LeafState::Fresh => Fr::from(0u64),
            LeafState::Used  => Fr::from(1u64),
            LeafState::Spent => Fr::from(2u64),
        }
    }

    /// 从域元素解码；非 `0/1/2` 返回 `None`。
    #[inline]
    pub fn from_fr(f: Fr) -> Option<Self> {
        let v = f.into_bigint().0[0];
        match v {
            0 => Some(LeafState::Fresh),
            1 => Some(LeafState::Used),
            2 => Some(LeafState::Spent),
            _ => None,
        }
    }

    /// 严格序：`FRESH ≺ USED ≺ SPENT`。
    #[inline]
    pub fn strict_lt(self, other: Self) -> bool {
        matches!(
            (self, other),
            (LeafState::Fresh, LeafState::Used)
                | (LeafState::Fresh, LeafState::Spent)
                | (LeafState::Used, LeafState::Spent)
        )
    }

    /// 合法后继。
    #[inline]
    pub fn next(self) -> Option<Self> {
        match self {
            LeafState::Fresh => Some(LeafState::Used),
            LeafState::Used  => Some(LeafState::Spent),
            LeafState::Spent => None,
        }
    }

    /// 两位编码 `(b1, b0)`：`Fresh = 00`，`Used = 01`，`Spent = 10`。
    #[inline]
    pub fn bits(self) -> (u64, u64) {
        match self {
            LeafState::Fresh => (0, 0),
            LeafState::Used  => (0, 1),
            LeafState::Spent => (1, 0),
        }
    }

    /// 与论文 `C_≺(x, y) = ¬x₁ ∧ (y₁ ∨ (¬x₀ ∧ y₀))` 对应的参考谓词。
    #[inline]
    pub fn strict_lt_circuit(x: Self, y: Self) -> bool {
        let (x1, x0) = x.bits();
        let (y1, y0) = y.bits();
        (x1 == 0) && (y1 == 1 || (x0 == 0 && y0 == 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_roundtrip() {
        for s in [LeafState::Fresh, LeafState::Used, LeafState::Spent] {
            assert_eq!(LeafState::from_fr(s.to_fr()), Some(s));
        }
    }

    #[test]
    fn strict_order_matches_paper_table() {
        // 论文附录 A 逐对枚举
        assert!(LeafState::strict_lt_circuit(LeafState::Fresh, LeafState::Used));
        assert!(LeafState::strict_lt_circuit(LeafState::Fresh, LeafState::Spent));
        assert!(LeafState::strict_lt_circuit(LeafState::Used, LeafState::Spent));
        assert!(!LeafState::strict_lt_circuit(LeafState::Used, LeafState::Fresh));
        assert!(!LeafState::strict_lt_circuit(LeafState::Spent, LeafState::Fresh));
        assert!(!LeafState::strict_lt_circuit(LeafState::Spent, LeafState::Used));
        for s in [LeafState::Fresh, LeafState::Used, LeafState::Spent] {
            assert!(!LeafState::strict_lt_circuit(s, s));
        }
        // 参考谓词与 `strict_lt` 一致
        for a in [LeafState::Fresh, LeafState::Used, LeafState::Spent] {
            for b in [LeafState::Fresh, LeafState::Used, LeafState::Spent] {
                assert_eq!(a.strict_lt(b), LeafState::strict_lt_circuit(a, b));
            }
        }
    }

    #[test]
    fn next_is_strict_lt() {
        for s in [LeafState::Fresh, LeafState::Used] {
            let n = s.next().unwrap();
            assert!(s.strict_lt(n));
        }
        assert!(LeafState::Spent.next().is_none());
    }
}
