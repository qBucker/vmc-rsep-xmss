//! RSEP-XMSS 端到端集成测试。
//!
//! 作为外部使用者访问 `rsep_xmss` 的公开 API，覆盖：
//! * 完整生命周期：keygen → sign → finalize → 全树耗尽
//! * 重放 / 篡改 / 跨叶混淆
//! * 序列化往返
//! * 验证器状态持久化模拟（save / load）

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsep_xmss::poseidon::PoseidonParams;
use rsep_xmss::proof;
use rsep_xmss::rsep::{
    self, RsepPublicKey, RsepSignature, Verdict, VerifierState,
};
use rsep_xmss::wots::WOTS_N;
use rsep_xmss::errors::RsepError;

fn poseidon() -> PoseidonParams {
    PoseidonParams::derive(b"rsep-xmss-integration")
}

/// 覆盖论文 §4.4 的强终止：整棵 h=2 树被完整耗尽后所有叶子
/// 处于 SPENT，且最终根与所有叶子为 Spent 的树一致。
#[test]
fn full_lifecycle_exhausts_tree() {
    let p = poseidon();
    let mut rng = ChaCha20Rng::seed_from_u64(0xFEED);
    let h = 2u8;
    let n = 1usize << h;
    let (public, mut secret) = rsep::keygen(&p, h, &mut rng).unwrap();
    let mut verifier = VerifierState::init(&public);

    let msg = [0xAAu8; WOTS_N];
    for i in 0..n as u64 {
        let sig = rsep::sign(&public, &mut secret, &msg, i, &mut rng).unwrap();
        assert!(matches!(
            verifier.verify_signature(&public, &msg, &sig).unwrap(),
            Verdict::Accept
        ));
        let fin = rsep::finalize(&public, &mut secret, i, &mut rng).unwrap();
        assert!(matches!(
            verifier.verify_finalization(&public, &fin).unwrap(),
            Verdict::Accept
        ));
    }

    // 所有叶子处于 SPENT
    assert!(secret
        .leaf_states
        .iter()
        .all(|s| *s == rsep_xmss::state::LeafState::Spent));
    // 计数器 = 2N
    assert_eq!(secret.counter, 2 * n as u64);
    // 验证器根与签名者根一致
    assert_eq!(verifier.cur_root, *secret.tree.last().unwrap().last().unwrap());
}

/// 重放已接受的签名必须被拒。
#[test]
fn cross_signer_replay_rejected() {
    let p = poseidon();
    let mut rng_a = ChaCha20Rng::seed_from_u64(0xA1);
    let mut rng_b = ChaCha20Rng::seed_from_u64(0xB2);
    let (pub_a, mut sec_a) = rsep::keygen(&p, 2, &mut rng_a).unwrap();
    let (_pub_b, _sec_b) = rsep::keygen(&p, 2, &mut rng_b).unwrap();

    let msg = [0x11u8; WOTS_N];
    let sig = rsep::sign(&pub_a, &mut sec_a, &msg, 0, &mut rng_a).unwrap();

    // 用 A 的验证器接受一次，再重放
    let mut verifier = VerifierState::init(&pub_a);
    assert!(matches!(
        verifier.verify_signature(&pub_a, &msg, &sig).unwrap(),
        Verdict::Accept
    ));
    assert!(matches!(
        verifier.verify_signature(&pub_a, &msg, &sig).unwrap(),
        Verdict::RejectStaleCounter
    ));
}

/// 篡改证明后必须被 Groth16 拒绝。
#[test]
fn tampered_proof_rejected() {
    let p = poseidon();
    let mut rng = ChaCha20Rng::seed_from_u64(0xCAFE);
    let (public, mut secret) = rsep::keygen(&p, 2, &mut rng).unwrap();
    let mut verifier = VerifierState::init(&public);

    let msg = [0x33u8; WOTS_N];
    let sig = rsep::sign(&public, &mut secret, &msg, 0, &mut rng).unwrap();

    // 序列化后篡改一个字节
    let mut bytes = proof::proof_to_bytes(&sig.proof).unwrap();
    bytes[10] ^= 0xFF;
    // 反序列化可能失败，也可能得到一个不同的证明；两种都算拒绝
    let tampered = match proof::proof_from_bytes(&bytes) {
        Ok(p) => p,
        Err(_) => return,
    };
    let tampered_sig = RsepSignature {
        xmss_sig: sig.xmss_sig.clone(),
        leaf_index: sig.leaf_index,
        proof: tampered,
        new_counter: sig.new_counter,
        new_root: sig.new_root,
    };
    match verifier.verify_signature(&public, &msg, &tampered_sig) {
        Ok(Verdict::RejectProof) => {}
        Err(RsepError::ProofSystem(_)) => {}
        other => panic!("expected RejectProof or ProofSystem error, got {:?}", other),
    }
}

/// 用 A 的 XMSS 签名与 B 的状态证明组合必须被拒。
#[test]
fn mismatched_xmss_and_proof_rejected() {
    let p = poseidon();
    let mut rng_a = ChaCha20Rng::seed_from_u64(0x11);
    let mut rng_b = ChaCha20Rng::seed_from_u64(0x22);
    let (pub_a, mut sec_a) = rsep::keygen(&p, 2, &mut rng_a).unwrap();
    let (pub_b, mut sec_b) = rsep::keygen(&p, 2, &mut rng_b).unwrap();

    let msg = [0x77u8; WOTS_N];
    let sig_a = rsep::sign(&pub_a, &mut sec_a, &msg, 0, &mut rng_a).unwrap();
    let sig_b = rsep::sign(&pub_b, &mut sec_b, &msg, 0, &mut rng_b).unwrap();

    let mixed = RsepSignature {
        xmss_sig: sig_a.xmss_sig.clone(),
        leaf_index: sig_a.leaf_index,
        proof: sig_b.proof.clone(),
        new_counter: sig_b.new_counter,
        new_root: sig_b.new_root,
    };
    let mut verifier = VerifierState::init(&pub_a);
    // XMSS 部分通过（A 的签名），但证明对 A 的根不成立
    match verifier.verify_signature(&pub_a, &msg, &mixed) {
        Ok(Verdict::RejectProof) => {}
        Ok(Verdict::RejectXmss) => {
            // 也接受——取决于 XMSS 与证明的哪一方先失败
        }
        other => panic!("expected rejection, got {:?}", other),
    }
}

/// 序列化 / 反序列化证明与 vk 往返。
#[test]
fn serialization_roundtrip() {
    let p = poseidon();
    let mut rng = ChaCha20Rng::seed_from_u64(0x5A5A);
    let (public, mut secret) = rsep::keygen(&p, 2, &mut rng).unwrap();

    // 证明往返
    let msg = [0x44u8; WOTS_N];
    let sig = rsep::sign(&public, &mut secret, &msg, 0, &mut rng).unwrap();
    let bytes = proof::proof_to_bytes(&sig.proof).unwrap();
    let back = proof::proof_from_bytes(&bytes).unwrap();
    let mut verifier = VerifierState::init(&public);
    let sig2 = RsepSignature {
        xmss_sig: sig.xmss_sig.clone(),
        leaf_index: sig.leaf_index,
        proof: back,
        new_counter: sig.new_counter,
        new_root: sig.new_root,
    };
    assert!(matches!(
        verifier.verify_signature(&public, &msg, &sig2).unwrap(),
        Verdict::Accept
    ));

    // vk 往返
    let vk_bytes = proof::vk_to_bytes(&public.sign_vk).unwrap();
    let _vk_back = proof::vk_from_bytes(&vk_bytes).unwrap();
}

/// 用错误的消息数字调用 XMSS 验证。
#[test]
fn wrong_message_short_circuits_before_proof() {
    let p = poseidon();
    let mut rng = ChaCha20Rng::seed_from_u64(0x99);
    let (public, mut secret) = rsep::keygen(&p, 2, &mut rng).unwrap();
    let mut verifier = VerifierState::init(&public);

    let msg = [0x10u8; WOTS_N];
    let sig = rsep::sign(&public, &mut secret, &msg, 0, &mut rng).unwrap();
    let bad = [0x20u8; WOTS_N];

    assert!(matches!(
        verifier.verify_signature(&public, &bad, &sig).unwrap(),
        Verdict::RejectXmss
    ));
    // 状态未变
    assert_eq!(verifier.last_counter, 0);
    assert_eq!(verifier.cur_root, public.state_root);
}

/// 模拟验证器状态持久化：序列化 `(cur_root, last_counter)`，
/// 重启后恢复并继续接受后续签名。
#[test]
fn verifier_state_persists_across_restart() {
    let p = poseidon();
    let mut rng = ChaCha20Rng::seed_from_u64(0x7777);
    let (public, mut secret) = rsep::keygen(&p, 3, &mut rng).unwrap();

    // 第一个验证器实例，接受 3 个签名
    let mut v1 = VerifierState::init(&public);
    let msg = [0x88u8; WOTS_N];
    let mut last_sig = None;
    for i in 0..3u64 {
        let sig = rsep::sign(&public, &mut secret, &msg, i, &mut rng).unwrap();
        assert!(matches!(
            v1.verify_signature(&public, &msg, &sig).unwrap(),
            Verdict::Accept
        ));
        last_sig = Some(sig);
    }
    let saved_root = v1.cur_root;
    let saved_counter = v1.last_counter;
    drop(v1);

    // 重启：从持久化状态恢复
    let mut v2 = VerifierState {
        cur_root: saved_root,
        last_counter: saved_counter,
    };

    // 重放最后一条签名被拒
    let last = last_sig.unwrap();
    assert!(matches!(
        v2.verify_signature(&public, &msg, &last).unwrap(),
        Verdict::RejectStaleCounter
    ));

    // 后续签名被接受
    let next = rsep::sign(&public, &mut secret, &msg, 3, &mut rng).unwrap();
    assert!(matches!(
        v2.verify_signature(&public, &msg, &next).unwrap(),
        Verdict::Accept
    ));
}

/// 签名者本地对同一叶子二次签名被拒（防止状态回滚前先自伤）。
#[test]
fn local_state_machine_enforced() {
    let p = poseidon();
    let mut rng = ChaCha20Rng::seed_from_u64(0x1234);
    let (_public, mut secret) = rsep::keygen(&p, 2, &mut rng).unwrap();
    let msg = [0x99u8; WOTS_N];

    let _ = rsep::sign(&_public, &mut secret, &msg, 1, &mut rng).unwrap();

    // 同一叶子再次签名被拒
    match rsep::sign(&_public, &mut secret, &msg, 1, &mut rng) {
        Err(RsepError::LeafStateMismatch { index, .. }) => assert_eq!(index, 1),
        Err(e) => panic!("expected LeafStateMismatch, got Err({:?})", e),
        Ok(_) => panic!("expected LeafStateMismatch, got Ok"),
    }

    // 直接调用 finalize 然后再次 finalize 也被拒
    let _ = rsep::finalize(&_public, &mut secret, 1, &mut rng).unwrap();
    match rsep::finalize(&_public, &mut secret, 1, &mut rng) {
        Err(RsepError::LeafStateMismatch { index, .. }) => assert_eq!(index, 1),
        Err(e) => panic!("expected LeafStateMismatch, got Err({:?})", e),
        Ok(_) => panic!("expected LeafStateMismatch, got Ok"),
    }
}
