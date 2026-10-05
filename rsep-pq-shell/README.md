# rsep-pq-shell — 后量子外壳实测 artifact 树

> 来源：2026-09-20 沙盒实测，完整报告见 [`PQ-外壳实测报告.md`](PQ-外壳实测报告.md)｜2026-10-02 从归档找回并复核（双哈希与论文 §7.5 逐字一致）
> 论文对应：§7.4（Post-Quantum Shells: Measured）与 §7.5（Code Availability and Reproducibility）

## 内容

| 路径 | 说明 | 哈希 |
|---|---|---|
| `wf-audit/` | Winterfell STARK 审计链 prover 源码（winterfell 0.13.1；`C_t = Poseidon([C_{t-1}, B_t, DS])[0]`，T=32） | — |
| `out/wf-audit-proof.bin` | 5-run bench 产出的 STARK 证明（57,589 B） | `8ddc9823…cd0e81` ✅ 2026-10-02 复核 |
| `out/wf-bench-5runs.md`、`out/wf-bench.txt` | prove 197.6 ms / verify 1.04 ms / 57,589 B 原始记录 | — |
| `out/wf-sha256.txt` | 原始 sha256 清单 | — |
| `rsep-guest.elf` | RISC Zero guest ELF（riscv32im-risc0-zkvm-elf，186,076 B） | `e086acf4…10f9` ✅ 复核 |
| `guest/`、`host/` | RZ guest 源码（poseidon/state 自仓库复制）+ host 源码（含 `src/bin/segprove.rs` 段级断点续传 prover） | — |
| `out/rz-exec.txt`、`out/rz-seg-timing.txt`、`out/rz-seg-verify.txt` | RZ 原始测量输出（50,865,966 cycles；段计时 331.3/333.6/335.6 s；verify 23.3 ms） | — |
| `build_guest.sh`、`recover.sh`、`recompile-o2.sh`、`run-bench.sh`、`warm-only.sh`、`checkpoint-daemon.sh` | 沙盒构建 / 自愈（幂等银行化）脚本 | — |
| `keccak-sys-build.rs`、`recursion-sys-build.rs`、`rv32im-sys-build.rs` | 三大 C++ 内核 crate 的 vendor 化 `build.rs` | — |
| `host-build.log` | RZ host 构建日志 | — |

## 未包含（派生二进制，按需重建）

- `rsep-pq-host.bin`（93 MB）、`segprove.bin`（89 MB）、`wf-audit-bin`（3.9 MB）——可由上述源码 + 脚本重建（wf-audit 已于 2026-10-02 本机重建成功，见复现记录）；sha256 记录见报告与 `out/wf-sha256.txt`。**注意**：从 zip 解出的二进制需 `chmod +x`（压缩包未保留可执行位）。
- **receipt 文件本体**（seg-000 = `a8dc2709…f3e569fc`）与 **packed program binary**（`64a34187…2ea9ba16`）：二者在沙盒回收时丢失，仅存哈希记录（报告 §3）。§7.5 的对应表述待文本阶段对齐。

## 复现

**Winterfell 轨**（任一 Linux x86_64，rust ≥ 1.87）：

```sh
cd wf-audit && cargo run --release   # 重新生成 out/wf-audit-proof.bin 与 bench 输出
```

**RISC Zero 轨**：见 `PQ-外壳实测报告.md` §6（需 rzup / risc0 工具链与内核重编；沙盒脚本已保留，recover.sh 幂等）；**本机（非沙盒）全量复跑重建配方见文末「本机构建与全量复跑」节**。

**本机复现（2026-10-02）**：wf-audit 已在 WSL2 x86-64（rustc 1.98.1）重建并复现——prove **≈130 ms（默认线程）/ ≈37 ms（`RAYON_NUM_THREADS=2`，稳定配置）**、verify ≈0.48 ms；**证明尺寸非定值**（21+ 次运行观察 57,589–59,830 B；机制 = `concurrent` 特性下 rayon `find_any` 的 grinding nonce 非确定；2 线程下复稳）；重建二进制与沙盒原版二进制产出字节级相同的证明（跨构建复现）。**prove 耗时对线程数高度敏感（20 线程 ~3.5× 并行开销）——引用耗时时必须注明线程配置。** 全部证据与分析见 `out/rerun-2026-10-02/README.md`；§7.4 的 "57,589 B / 尺寸确定" 表述修订已列入文本相待办。

## 环境

沙盒：**2 核 / 4 GB 无 swap**，cargo 1.98.1（rustc 1.98.1）；Winterfell 0.13.1；RISC Zero 3.0.6（dev-mode OFF；内核以 -O2 编译）。与论文 Table 3 caption 的 "2-core sandbox, 4 GB RAM" 一致。

## 本机构建与全量复跑（2026-10-05，论文批）

WSL2 笔记本（i7-13650HX，实机 16 GB；`.wslconfig` 声明 20 核 / 12 GiB / swap 8 GB 并写死），
O2 内核，单会话全量递归复合：**端到端 99.87 min**（旧投影口径 22.4 h 的 ≈13×），
最终 succinct receipt 223,270 B、verify 11.5 ms、峰值内存 4.59 GiB（预算 38%）。
数字与归档见 `PQ-外壳实测报告.md` §7 与 `../measurements/raw/zkvm-full-v1-*`（SHA256SUMS 52/52）。

**重建配方**（三件齐备即可从零复现构建）：

1. **vendor 三包**（不入库，72 MB）：从 crates.io `.crate`（4.0.3）解出
   `risc0-circuit-{rv32im,recursion,keccak}-sys` 至 `vendor/`，替换其 `build.rs` 为
   本目录跟踪的三份 shim（`rv32im-sys-build.rs` / `recursion-sys-build.rs` /
   `keccak-sys-build.rs`）；`host/Cargo.toml` 的 `[patch.crates-io]` 指向 `vendor/`。
2. **O2 内核对象**：`sh recompile-o2.sh`（本机版：源码 = `vendor/<crate>/kernels/cxx`，
   对象落 `/tmp/o2-obj/<rv|rec|kk>-obj`，幂等断点续跑；验收对象数 7/8/23）。
   shim 的 `pick()` 优先生效于 `/tmp/o2-obj`。
3. **递归 zkr 资产**：`~/.cache/risc0-artifacts/recursion_zkr.zip`
   （59,768,781 B，sha256 `744b999f…d8849`；经 `RECURSION_SRC_PATH` 后门投喂
   `risc0-circuit-recursion-4.0.5/build.rs`）。

```sh
cd host
cargo clean -p risc0-circuit-rv32im-sys -p risc0-circuit-recursion-sys -p risc0-circuit-keccak-sys --release
RECURSION_SRC_PATH=~/.cache/risc0-artifacts/recursion_zkr.zip cargo build --release --bin smoke --bin full
cd ..
sh run-smoke.sh 18 1                  # 微冒烟（O2 时序/内存核验）
sh run-full.sh 19 ../rsep-guest.elf   # 全量批（三级 checkpoint；host/out/full-v1/）
```

⚠️ `cargo clean -p` **必须带 `--release`**（不带只清 debug 档、静默 "Removed 0 files"，会带着旧内核假重建）。

**工具**：`host/src/bin/smoke.rs`（真实段 receipt + 显式 lift/join 递归聚合，冒烟 v2）、
`host/src/bin/full.rs`（全量驱动：全 execute → 逐段 prove+verify → lift ×N → join 树 →
`Receipt::new(…).verify(image_id)` 全覆盖校验 + journal 对账；checkpoint 断点续跑 + meta 同构守卫）、
`run-smoke.sh` / `run-full.sh`（环境披露头 + RSS 曲线采样）。

**备忘**：本批全量重生成全部段 receipt（po2=19 / 108 段），旧「seg-000 receipt 丢失」缺口
对本批不再适用（沙盒期哈希记录保留于报告 §3 作历史）。
