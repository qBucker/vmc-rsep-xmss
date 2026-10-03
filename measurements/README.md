# measurements — 测量记录与口径

> 配套：`notes/measurements.md`（全程总汇与论文对照）｜`examples/measure.rs`（测量程序）｜`examples/baseline.rs`（同会话 A/B 探测）
> 运行：`cargo run --release --example measure -- <h> [iters] [msg_byte]`（msg 默认 0x77；iters=5）
> 　　：`cargo run --release --example baseline -- <h> [iters]`（plain XMSS vs RSEP-XMSS）

## 轮次

| 轮 | 时间 | 条件 | 日志 |
|---|---|---|---|
| v1 | 2026-10-01 | msg=0x42；与 h=16 keygen 存在并发 | `raw/measure-*.log` |
| v2 | 2026-10-01/02 | msg=0x77（此前权威口径）；部分并发 | `raw/measure2-*.log` |
| v3 | 2026-10-02 | msg=0x77；`taskset -c 0,1` 双核钉住；顺序独立单跑 | `raw/measure-v3-*.log` |
| v4（canonical） | 2026-10-02 | Docker `--cpus=2 --memory=4g`（canonical 口径） | `raw/measure-v4-*.log` |
| v5 | 2026-10-03 | 同容器（重建镜像，含 `examples/baseline.rs`）；baseline 同会话 A/B + per-event 微基准 | `raw/baseline-v5-h10.log`、`raw/per-event-bench-v5.txt` |

## 纪律

1. 跨轮一致性检查：v1↔v2 聚合量差 ≤1.2%；**v2→v3 差异 ±2~9%（符号不一）**——归因已完成：**unpinned 对照 ≈ pinned（keygen 差 0.07%）→ 钉核零影响，差异为会话/热态噪声**（见 `measure-unpin-h10.log`）；canonical 数字以 v4（容器化）定案。
2. 原始日志只增不改；用 `sha256sum -c SHA256SUMS` 校验（v3 的 h=16 日志在跑完后追加）。
3. measured / computed / projected 标注纪律见 `notes/measurements.md §6`。
