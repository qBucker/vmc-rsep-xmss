//! RFC 8391 §2.5 ADRS：32 字节地址结构。
//!
//! 字节布局（大端）：
//!
//! | 偏移 | 长度 | OTS (type 0) | LTREE (type 1) / HASH_TREE (type 2) |
//! |------|------|--------------|--------------------------------------|
//! | 0    | 4    | layer        | layer        |
//! | 4    | 8    | tree         | tree         |
//! | 12   | 4    | type         | type         |
//! | 16   | 4    | OTS 地址     | L-tree 地址（= 该 WOTS 密钥的 OTS 索引）|
//! | 20   | 4    | chain 地址   | tree height  |
//! | 24   | 4    | hash 地址    | tree index   |
//! | 28   | 4    | key & mask   | key & mask   |
//!
//! 即 word 4 是 OTS 与 L-tree 共用的「地址」字段，tree height /
//! tree index 占 word 5 / word 6——与 OTS 的 chain / hash 同位。
//! （第四波实测发现：此前二者错写在 word 4 / word 5，ltree 中
//! set_tree_height 会覆盖 OTS 索引，破坏 RFC 8391 的地址域分离。）

/// OTS 哈希地址类型（RFC 8391 §2.5.1）。
pub const TYPE_OTS: u32 = 0;
/// L-tree 地址类型（RFC 8391 §2.5.2）。
pub const TYPE_LTREE: u32 = 1;
/// 主 Merkle 树哈希地址类型（RFC 8391 §2.5.3）。
pub const TYPE_HASH_TREE: u32 = 2;

/// RFC 8391 §2.5 ADRS。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct Adrs([u8; 32]);

impl Adrs {
    /// 全零 ADRS。
    #[inline]
    pub const fn zero() -> Self {
        Adrs([0u8; 32])
    }

    /// 等价于 [`Adrs::zero`]，为可读性提供别名。
    #[inline]
    pub fn new() -> Self {
        Self::zero()
    }

    /// 设置 layer（字节 0..4）。
    #[inline]
    pub fn set_layer(&mut self, v: u32) {
        self.0[0..4].copy_from_slice(&v.to_be_bytes());
    }
    /// 设置 tree（字节 4..12）。
    #[inline]
    pub fn set_tree(&mut self, v: u64) {
        self.0[4..12].copy_from_slice(&v.to_be_bytes());
    }
    /// 设置 type（字节 12..16）。
    #[inline]
    pub fn set_type(&mut self, v: u32) {
        self.0[12..16].copy_from_slice(&v.to_be_bytes());
    }
    /// 设置 OTS 索引（字节 16..20）。
    #[inline]
    pub fn set_ots(&mut self, v: u32) {
        self.0[16..20].copy_from_slice(&v.to_be_bytes());
    }
    /// 设置 chain 索引（字节 20..24）。
    #[inline]
    pub fn set_chain(&mut self, v: u32) {
        self.0[20..24].copy_from_slice(&v.to_be_bytes());
    }
    /// 设置 hash 索引（字节 24..28）。
    #[inline]
    pub fn set_hash(&mut self, v: u32) {
        self.0[24..28].copy_from_slice(&v.to_be_bytes());
    }
    /// 设置 key & mask（字节 28..32）。
    #[inline]
    pub fn set_key_mask(&mut self, v: u32) {
        self.0[28..32].copy_from_slice(&v.to_be_bytes());
    }

    /// LTREE / HASH_TREE 层高（字节 20..24，RFC 8391 §2.5 word 5）。
    #[inline]
    pub fn set_tree_height(&mut self, v: u32) {
        self.0[20..24].copy_from_slice(&v.to_be_bytes());
    }
    /// LTREE / HASH_TREE 节点索引（字节 24..28，word 6）。
    #[inline]
    pub fn set_tree_index(&mut self, v: u32) {
        self.0[24..28].copy_from_slice(&v.to_be_bytes());
    }

    /// 不可变 32 字节视图。
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// 可变 32 字节视图。
    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl AsRef<[u8]> for Adrs {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_offsets_are_disjoint() {
        let mut a = Adrs::zero();
        a.set_layer(0xAAAA_AAAA);
        a.set_tree(0xBBBB_BBBB_BBBB_BBBB);
        a.set_type(TYPE_OTS);
        a.set_ots(0xCCCC_CCCC);
        a.set_chain(0xDDDD_DDDD);
        a.set_hash(0xEEEE_EEEE);
        a.set_key_mask(0xFFFF_FFFF);
        let b = a.as_bytes();
        assert_eq!(&b[0..4],   &0xAAAA_AAAAu32.to_be_bytes());
        assert_eq!(&b[4..12],  &0xBBBB_BBBB_BBBB_BBBBu64.to_be_bytes());
        assert_eq!(&b[12..16], &0u32.to_be_bytes());
        assert_eq!(&b[16..20], &0xCCCC_CCCCu32.to_be_bytes());
        assert_eq!(&b[20..24], &0xDDDD_DDDDu32.to_be_bytes());
        assert_eq!(&b[24..28], &0xEEEE_EEEEu32.to_be_bytes());
        assert_eq!(&b[28..32], &0xFFFF_FFFFu32.to_be_bytes());
    }

    /// LTREE 型地址的字段互斥性：set_ots / set_tree_height /
    /// set_tree_index 依次调用后，三者都必须保留（回归：第四波
    /// 实测发现 tree_height 曾错写 word 4 覆盖 OTS 索引）。
    #[test]
    fn ltree_fields_are_disjoint() {
        let mut a = Adrs::zero();
        a.set_type(TYPE_LTREE);
        a.set_ots(0x1111_1111);
        a.set_tree_height(0x2222_2222);
        a.set_tree_index(0x3333_3333);
        a.set_key_mask(0x4444_4444);
        let b = a.as_bytes();
        assert_eq!(&b[16..20], &0x1111_1111u32.to_be_bytes(), "ots");
        assert_eq!(&b[20..24], &0x2222_2222u32.to_be_bytes(), "tree height");
        assert_eq!(&b[24..28], &0x3333_3333u32.to_be_bytes(), "tree index");
        assert_eq!(&b[28..32], &0x4444_4444u32.to_be_bytes(), "key & mask");
    }
}
