//! RSEP-XMSS 性能基准。
//!
//! 运行：`cargo bench`
//!
//! 三个树高：h ∈ {2, 4, 6}。h=10 只在 `--features slow-bench` 下
//! 运行（keygen 会分钟级）。

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsep_xmss::poseidon::PoseidonParams;
use rsep_xmss::rsep::{self, VerifierState};
use rsep_xmss::wots::WOTS_N;

fn bench_poseidon_hash2(c: &mut Criterion) {
    let p = PoseidonParams::derive(b"bench");
    let mut group = c.benchmark_group("poseidon_hash2");
    group.throughput(Throughput::Elements(1));
    group.bench_function("one_hash", |b| {
        b.iter(|| {
            let _ = p.hash2(
                rsep_xmss::Fr::from(1u64),
                rsep_xmss::Fr::from(2u64),
            );
        })
    });
    group.finish();
}

fn bench_keygen(c: &mut Criterion) {
    let p = PoseidonParams::derive(b"bench");
    let mut group = c.benchmark_group("keygen");
    group.sample_size(10);
    for h in [2u8, 4] {
        group.bench_with_input(BenchmarkId::from_parameter(h), &h, |b, &h| {
            b.iter(|| {
                let mut rng = ChaCha20Rng::seed_from_u64(0);
                let _ = rsep::keygen(&p, h, &mut rng).unwrap();
            })
        });
    }
    group.finish();
}

fn bench_sign_verify(c: &mut Criterion) {
    let p = PoseidonParams::derive(b"bench");
    let mut group = c.benchmark_group("sign_verify");
    group.sample_size(20);
    for h in [2u8, 4] {
        let mut rng = ChaCha20Rng::seed_from_u64(0xCAFE);
        let (public, mut secret) = rsep::keygen(&p, h, &mut rng).unwrap();
        let msg = [0x42u8; WOTS_N];

        group.bench_with_input(BenchmarkId::new("sign", h), &h, |b, _| {
            let mut local_secret = rsep::keygen(&p, h,
                &mut ChaCha20Rng::seed_from_u64(0xCAFE)).unwrap().1;
            let mut local_rng = ChaCha20Rng::seed_from_u64(0xDEAD);
            let mut idx = 0u64;
            b.iter(|| {
                let _ = rsep::sign(&public, &mut local_secret, &msg,
                                   idx, &mut local_rng).unwrap();
                idx += 1;
            })
        });

        // 预先准备一批签名，避免在 verify benchmark 里混入 sign 成本
        let sig = rsep::sign(&public, &mut secret, &msg, 0,
                             &mut ChaCha20Rng::seed_from_u64(1)).unwrap();
        group.bench_with_input(BenchmarkId::new("verify", h), &h, |b, _| {
            b.iter(|| {
                let mut v = VerifierState::init(&public);
                let _ = v.verify_signature(&public, &msg, &sig).unwrap();
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_poseidon_hash2,
    bench_keygen,
    bench_sign_verify,
);
criterion_main!(benches);
