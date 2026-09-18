//! A2 统计实验数据导出工具（调试用途，不进发布 API）。
//!
//! 用法：cargo run --release --example emit_bitstream -- <mode> <out_dir>
//! mode:
//!   poseidon-counter    计数器输入 → Poseidon hash2 比特流（100×10^6 比特）
//!   blake2b-counter     计数器输入 → Blake2b-512 比特流（对照组）
//!   poseidon-random     随机输入（ChaCha20 固定种子）→ Poseidon 比特流
//!   blake2b-random      随机输入 → Blake2b-512 比特流（对照组）
//!   avalanche-poseidon  雪崩实验：n=10,000 试验 × 253 输入位，输出 CSV
//!   avalanche-blake2b   雪崩对照组（256 输入位 × 512 输出位）
//!   all                 依次全部执行
//!
//! 口径声明（写进 Appendix S 的注记）：
//! - Poseidon 输出按 canonical big-endian 32 字节序列化；BN254 标量域
//!   p ≈ 2^254，故 256 比特编码的高 ~2 位天然偏 0——这是编码偏差，
//!   不是哈希缺陷，800-22 结果中与低位分开报告。
//! - 雪崩输入域为 253 比特串（LE 数组屏蔽高 3 位），恰好无偏嵌入 Fr。
//! - Poseidon 域分离串：b"rsep-xmss-a2-stats"。

use blake2::{Blake2b512, Digest};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rsep_xmss::poseidon::PoseidonParams;
use rsep_xmss::Fr;
use ark_ff::{BigInteger, PrimeField};
use std::fs::File;
use std::io::{BufWriter, Write};

/// 比特流总比特数：100 条序列 × 每条 10^6 比特（SP 800-22 推荐口径）
const TOTAL_BITS: usize = 100_000_000;
const STREAM_BYTES: usize = TOTAL_BITS / 8; // 12_500_000

/// 雪崩试验数（A2 设计文档：n = 10,000）
const AVALANCHE_TRIALS: usize = 10_000;
/// Poseidon 雪崩输入位数（253 比特恰好嵌入 Fr）
const POSEIDON_INPUT_BITS: usize = 253;
/// Blake2b 雪崩输入位数（256 比特全域）
const BLAKE_INPUT_BITS: usize = 256;

const POSEIDON_DOMAIN: &[u8] = b"rsep-xmss-a2-stats";
const RNG_SEED_STREAM: u64 = 0xA2_57_12EA; // 固定种子，可复现
const RNG_SEED_AVALANCHE: u64 = 0xA1_ABC;

fn fr_bytes(x: Fr) -> [u8; 32] {
    let v = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// 从 253 比特随机串构造 Fr（LE 数组屏蔽高 3 位，值 < 2^253 < p，无取模偏差）
fn rand_fr_253(rng: &mut ChaCha20Rng) -> ([u8; 32], Fr) {
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    buf[31] &= 0b0001_1111; // 253 = 256 - 3
    let x = Fr::from_le_bytes_mod_order(&buf);
    (buf, x)
}

fn stream_poseidon_counter(out_dir: &str) {
    let params = PoseidonParams::derive(POSEIDON_DOMAIN);
    let path = format!("{out_dir}/poseidon-counter.bin");
    let mut w = BufWriter::new(File::create(&path).unwrap());
    let mut written = 0usize;
    let mut i = 0u64;
    while written < STREAM_BYTES {
        let h = params.hash2(Fr::from(i), Fr::from(0u64));
        let b = fr_bytes(h);
        let take = (STREAM_BYTES - written).min(32);
        w.write_all(&b[..take]).unwrap();
        written += take;
        i += 1;
    }
    println!("poseidon-counter: {} hashes -> {}", i, path);
}

fn stream_blake2b_counter(out_dir: &str) {
    let path = format!("{out_dir}/blake2b-counter.bin");
    let mut w = BufWriter::new(File::create(&path).unwrap());
    let mut written = 0usize;
    let mut i = 0u64;
    while written < STREAM_BYTES {
        let h = Blake2b512::digest(i.to_le_bytes());
        let take = (STREAM_BYTES - written).min(64);
        w.write_all(&h[..take]).unwrap();
        written += take;
        i += 1;
    }
    println!("blake2b-counter: {} hashes -> {}", i, path);
}

fn stream_poseidon_random(out_dir: &str) {
    let params = PoseidonParams::derive(POSEIDON_DOMAIN);
    let mut rng = ChaCha20Rng::seed_from_u64(RNG_SEED_STREAM);
    let path = format!("{out_dir}/poseidon-random.bin");
    let mut w = BufWriter::new(File::create(&path).unwrap());
    let mut written = 0usize;
    let mut i = 0u64;
    while written < STREAM_BYTES {
        let (_, a) = rand_fr_253(&mut rng);
        let b = fr_bytes(params.hash2(a, Fr::from(0u64)));
        let take = (STREAM_BYTES - written).min(32);
        w.write_all(&b[..take]).unwrap();
        written += take;
        i += 1;
    }
    println!("poseidon-random: {} hashes -> {}", i, path);
}

fn stream_blake2b_random(out_dir: &str) {
    let mut rng = ChaCha20Rng::seed_from_u64(RNG_SEED_STREAM);
    let path = format!("{out_dir}/blake2b-random.bin");
    let mut w = BufWriter::new(File::create(&path).unwrap());
    let mut written = 0usize;
    let mut i = 0u64;
    while written < STREAM_BYTES {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let h = Blake2b512::digest(buf);
        let take = (STREAM_BYTES - written).min(64);
        w.write_all(&h[..take]).unwrap();
        written += take;
        i += 1;
    }
    println!("blake2b-random: {} hashes -> {}", i, path);
}

fn flip_bit_le(buf: &[u8; 32], j: usize) -> [u8; 32] {
    let mut b = *buf;
    b[j / 8] ^= 1 << (j % 8);
    b
}

fn avalanche_poseidon(out_dir: &str) {
    let params = PoseidonParams::derive(POSEIDON_DOMAIN);
    let mut rng = ChaCha20Rng::seed_from_u64(RNG_SEED_AVALANCHE);
    let mut per_pos = vec![0u64; POSEIDON_INPUT_BITS];
    let mut per_byte = [0u64; 32];
    let mut total_flips = 0u64;
    let mut total_bits = 0u64;
    for _ in 0..AVALANCHE_TRIALS {
        let (le, a) = rand_fr_253(&mut rng);
        let base = fr_bytes(params.hash2(a, Fr::from(0u64)));
        for j in 0..POSEIDON_INPUT_BITS {
            let ap = Fr::from_le_bytes_mod_order(&flip_bit_le(&le, j));
            let hp = fr_bytes(params.hash2(ap, Fr::from(0u64)));
            let mut c = 0u64;
            for k in 0..32 {
                let d = (base[k] ^ hp[k]).count_ones() as u64;
                c += d;
                per_byte[k] += d;
            }
            per_pos[j] += c;
            total_flips += c;
            total_bits += 256;
        }
    }
    let denom_pair = (AVALANCHE_TRIALS * POSEIDON_INPUT_BITS) as f64;
    let path = format!("{out_dir}/avalanche-poseidon.csv");
    let mut s = String::from("bit_position,output_flip_rate\n");
    for j in 0..POSEIDON_INPUT_BITS {
        s.push_str(&format!(
            "{},{:.6}\n",
            j,
            per_pos[j] as f64 / (AVALANCHE_TRIALS as f64 * 256.0)
        ));
    }
    s.push_str(&format!(
        "overall,{:.6}\n",
        total_flips as f64 / total_bits as f64
    ));
    // 逐字节分解：b[0] 为高字节（编码偏差区），b[1..32] 为低 248 位（统计有效区）
    for k in 0..32 {
        s.push_str(&format!(
            "byte_{},{:.6}\n",
            k,
            per_byte[k] as f64 / (denom_pair * 8.0)
        ));
    }
    let low248 = per_byte[1..].iter().sum::<u64>() as f64 / (denom_pair * 248.0);
    s.push_str(&format!("overall_low248,{low248:.6}\n"));
    std::fs::write(&path, s).unwrap();
    println!(
        "avalanche-poseidon: {} trials x {} bits, overall flip rate {:.6} -> {}",
        AVALANCHE_TRIALS,
        POSEIDON_INPUT_BITS,
        total_flips as f64 / total_bits as f64,
        path
    );
}

fn avalanche_blake2b(out_dir: &str) {
    let mut rng = ChaCha20Rng::seed_from_u64(RNG_SEED_AVALANCHE);
    let mut per_pos = vec![0u64; BLAKE_INPUT_BITS];
    let mut total_flips = 0u64;
    let mut total_bits = 0u64;
    for _ in 0..AVALANCHE_TRIALS {
        let mut le = [0u8; 32];
        rng.fill_bytes(&mut le);
        let base = Blake2b512::digest(le);
        for j in 0..BLAKE_INPUT_BITS {
            let hp = Blake2b512::digest(flip_bit_le(&le, j));
            let mut c = 0u64;
            for k in 0..64 {
                c += (base[k] ^ hp[k]).count_ones() as u64;
            }
            per_pos[j] += c;
            total_flips += c;
            total_bits += 512;
        }
    }
    let path = format!("{out_dir}/avalanche-blake2b.csv");
    let mut s = String::from("bit_position,output_flip_rate\n");
    for j in 0..BLAKE_INPUT_BITS {
        s.push_str(&format!(
            "{},{:.6}\n",
            j,
            per_pos[j] as f64 / (AVALANCHE_TRIALS as f64 * 512.0)
        ));
    }
    s.push_str(&format!(
        "overall,{:.6}\n",
        total_flips as f64 / total_bits as f64
    ));
    std::fs::write(&path, s).unwrap();
    println!(
        "avalanche-blake2b: {} trials x {} bits, overall flip rate {:.6} -> {}",
        AVALANCHE_TRIALS,
        BLAKE_INPUT_BITS,
        total_flips as f64 / total_bits as f64,
        path
    );
}

/// MSB-first 位打包器：把每个哈希值的低 254 比特（去头 2 位）无缝拼接
struct BitPacker254 {
    acc: u64,
    nbits: u32,
}

impl BitPacker254 {
    fn new() -> Self {
        Self { acc: 0, nbits: 0 }
    }
    /// 输入 32 字节大端编码，丢弃最高 2 位，写入剩余 254 位；返回凑齐的字节
    fn push(&mut self, b: &[u8; 32], out: &mut Vec<u8>) {
        // 254 位 = 低 6 位 of b[0] + b[1..32]（31 字节 = 248 位）
        let mut bits = [0u8; 32];
        bits[0] = b[0] & 0x3F;
        bits[1..].copy_from_slice(&b[1..]);
        // 逐位 MSB-first 喂入
        for i in 0..254 {
            let byte = bits[i / 8];
            let bit = (byte >> (7 - (i % 8))) & 1;
            self.acc = (self.acc << 1) | bit as u64;
            self.nbits += 1;
            if self.nbits == 8 {
                out.push(self.acc as u8);
                self.acc = 0;
                self.nbits = 0;
            }
        }
    }
}

fn stream_poseidon_counter_254(out_dir: &str) {
    let params = PoseidonParams::derive(POSEIDON_DOMAIN);
    let path = format!("{out_dir}/poseidon-counter-254.bin");
    let mut w = BufWriter::new(File::create(&path).unwrap());
    let mut pk = BitPacker254::new();
    let mut written = 0usize;
    let mut i = 0u64;
    let mut buf = Vec::with_capacity(64);
    while written < STREAM_BYTES {
        let b = fr_bytes(params.hash2(Fr::from(i), Fr::from(0u64)));
        pk.push(&b, &mut buf);
        if buf.len() >= 4096 {
            let take = (STREAM_BYTES - written).min(buf.len());
            w.write_all(&buf[..take]).unwrap();
            written += take;
            buf.drain(..take);
        }
        i += 1;
    }
    println!("poseidon-counter-254: {} hashes -> {}", i, path);
}

fn stream_poseidon_random_254(out_dir: &str) {
    let params = PoseidonParams::derive(POSEIDON_DOMAIN);
    let mut rng = ChaCha20Rng::seed_from_u64(RNG_SEED_STREAM);
    let path = format!("{out_dir}/poseidon-random-254.bin");
    let mut w = BufWriter::new(File::create(&path).unwrap());
    let mut pk = BitPacker254::new();
    let mut written = 0usize;
    let mut i = 0u64;
    let mut buf = Vec::with_capacity(64);
    while written < STREAM_BYTES {
        let (_, a) = rand_fr_253(&mut rng);
        let b = fr_bytes(params.hash2(a, Fr::from(0u64)));
        pk.push(&b, &mut buf);
        if buf.len() >= 4096 {
            let take = (STREAM_BYTES - written).min(buf.len());
            w.write_all(&buf[..take]).unwrap();
            written += take;
            buf.drain(..take);
        }
        i += 1;
    }
    println!("poseidon-random-254: {} hashes -> {}", i, path);
}

/// 248 位口径：取 32 字节大端编码的低 31 字节（b[1..32]）。
/// 依据：x 在 [0,p) 上均匀 ⇒ x mod 2^248 各残类的计数差 ≤ 1，
/// 统计偏差 ~2^-248 量级，可忽略。高字节整体舍弃，不做位级拼接。
fn stream_poseidon_counter_248(out_dir: &str) {
    let params = PoseidonParams::derive(POSEIDON_DOMAIN);
    let path = format!("{out_dir}/poseidon-counter-248.bin");
    let mut w = BufWriter::new(File::create(&path).unwrap());
    let mut written = 0usize;
    let mut i = 0u64;
    while written < STREAM_BYTES {
        let b = fr_bytes(params.hash2(Fr::from(i), Fr::from(0u64)));
        let take = (STREAM_BYTES - written).min(31);
        w.write_all(&b[1..1 + take]).unwrap();
        written += take;
        i += 1;
    }
    println!("poseidon-counter-248: {} hashes -> {}", i, path);
}

fn stream_poseidon_random_248(out_dir: &str) {
    let params = PoseidonParams::derive(POSEIDON_DOMAIN);
    let mut rng = ChaCha20Rng::seed_from_u64(RNG_SEED_STREAM);
    let path = format!("{out_dir}/poseidon-random-248.bin");
    let mut w = BufWriter::new(File::create(&path).unwrap());
    let mut written = 0usize;
    let mut i = 0u64;
    while written < STREAM_BYTES {
        let (_, a) = rand_fr_253(&mut rng);
        let b = fr_bytes(params.hash2(a, Fr::from(0u64)));
        let take = (STREAM_BYTES - written).min(31);
        w.write_all(&b[1..1 + take]).unwrap();
        written += take;
        i += 1;
    }
    println!("poseidon-random-248: {} hashes -> {}", i, path);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: emit_bitstream <mode> <out_dir>");
        std::process::exit(2);
    }
    let (mode, out_dir) = (args[1].as_str(), args[2].as_str());
    std::fs::create_dir_all(out_dir).unwrap();
    match mode {
        "poseidon-counter" => stream_poseidon_counter(out_dir),
        "blake2b-counter" => stream_blake2b_counter(out_dir),
        "poseidon-random" => stream_poseidon_random(out_dir),
        "blake2b-random" => stream_blake2b_random(out_dir),
        "poseidon-counter-254" => stream_poseidon_counter_254(out_dir),
        "poseidon-random-254" => stream_poseidon_random_254(out_dir),
        "poseidon-counter-248" => stream_poseidon_counter_248(out_dir),
        "poseidon-random-248" => stream_poseidon_random_248(out_dir),
        "avalanche-poseidon" => avalanche_poseidon(out_dir),
        "avalanche-blake2b" => avalanche_blake2b(out_dir),
        "all" => {
            stream_poseidon_counter(out_dir);
            stream_blake2b_counter(out_dir);
            stream_poseidon_random(out_dir);
            stream_blake2b_random(out_dir);
            stream_poseidon_counter_248(out_dir);
            stream_poseidon_random_248(out_dir);
            avalanche_poseidon(out_dir);
            avalanche_blake2b(out_dir);
        }
        _ => {
            eprintln!("unknown mode: {mode}");
            std::process::exit(2);
        }
    }
}
