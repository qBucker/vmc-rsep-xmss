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

**RISC Zero 轨**：见 `PQ-外壳实测报告.md` §6（需 rzup / risc0 工具链与内核重编；沙盒脚本已保留，recover.sh 幂等）。

**本机复现（2026-10-02）**：wf-audit 已在 WSL2 x86-64（rustc 1.98.1）重建并复现——prove **≈130 ms（默认线程）/ ≈37 ms（`RAYON_NUM_THREADS=2`，稳定配置）**、verify ≈0.48 ms；**证明尺寸非定值**（21+ 次运行观察 57,589–59,830 B；机制 = `concurrent` 特性下 rayon `find_any` 的 grinding nonce 非确定；2 线程下复稳）；重建二进制与沙盒原版二进制产出字节级相同的证明（跨构建复现）。**prove 耗时对线程数高度敏感（20 线程 ~3.5× 并行开销）——引用耗时时必须注明线程配置。** 全部证据与分析见 `out/rerun-2026-10-02/README.md`；§7.4 的 "57,589 B / 尺寸确定" 表述修订已列入文本相待办。

## 环境

沙盒：**2 核 / 4 GB 无 swap**，cargo 1.98.1（rustc 1.98.1）；Winterfell 0.13.1；RISC Zero 3.0.6（dev-mode OFF；内核以 -O2 编译）。与论文 Table 3 caption 的 "2-core sandbox, 4 GB RAM" 一致。
