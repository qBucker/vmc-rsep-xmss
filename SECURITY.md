# Security Notes

## 已实现的安全性质

* **MU（单调不可伪造性）**：`VerifierState::verify_signature` 将
  证明的旧根固定为验证器自己的 `cur_root`，禁止对陈旧根的认证。
* **AUD（可审计性）**：`new_root` 进入验证器状态；若外部锚定
  （账本、CT 日志），任何回滚都留下可提取证据。
* **零知识**：`RsepSignature` 不含 `auth_path / v_old / v_new`；
  真 Groth16 的 `verify` 不接收 witness。
* **常量时间**：**未实现**（见下）。

## 部署前必须闭合的硬门槛

### 1. 可信设置（阻塞性）

`proof::setup` 使用 `generate_random_parameters_with_reduction`，
即**单方随机参数**。参数生成者持有 trapdoor，可伪造任意证明。

生产部署必须：
1. 执行 MPC 仪式（如 Powers of Tau + 电路特定阶段）。
2. 通过 `proof::vk_from_bytes` / `proof::pk_from_bytes` 加载
   仪式产物。
3. 校验仪式产物与电路哈希的绑定。

### 2. Poseidon 常量（阻塞性）

`PoseidonParams::derive` 使用 Blake2b 派生常量，**非规范
Grain-LFSR**。与规范 Poseidon 向量不互操作。

生产部署必须替换为规范参数向量。替换点：`poseidon.rs` 的
`PoseidonParams::derive`。

### 3. 验证器状态持久化

`VerifierState` 的 `(cur_root, last_counter)` 必须：
* 原子写入（崩溃时不产生部分更新）。
* 单调递增（禁止回滚到旧状态）。
* 建议：锚定到外部账本（Certificate Transparency 风格）。

本 crate **不做**持久化。参考 `tests/integration.rs` 的
`verifier_state_persists_across_restart` 了解接口。

### 4. 签名者状态持久化

`RsepKeyPair` 的 `counter` 与 `tree` 更新必须：
* 原子且单调。
* 崩溃恢复时保证 `counter` 不回滚。
* 建议：append-only 日志 + fsync；或硬件单调计数器。

### 5. 常数时间

以下操作目前非常数时间：

* `rsep::sign` 中的 `leaf_states[index]` 索引访问。
* `update_state_leaf` 中的路径更新（`index` 决定访问模式）。
* `RsepKeyPair::xmss.sign` 中的 `sk_seeds[index]` 访问。

若威胁模型包含旁路信道攻击，必须：
* 用 `subtle::ConstantTimeEq` 替换索引比较。
* 用线性扫描 + 掩码替换直接索引。
* 或在受控环境中部署（无本地攻击者）。

### 6. 终结权限

`verify_finalization` **不检查 XMSS 签名**（论文 Algorithm 4
的设计）。任何知道当前状态树的人都能生成合法终结证明。

若生产部署需要限制终结权限，必须在协议层叠加（例如：终结
证明只用于内部控制流，不产生外部可观察效果）。

### 7. 消息哈希

`WOTS_N` 为 32 字节，当前直接对 32 字节消息签名。若要签名任
意长度消息，调用方必须先做抗碰撞哈希（Poseidon 或 SHA-256）
并将其填入 `[u8; 32]`。本 crate **不做**消息哈希。

### 8. 曲线安全度（两层问题）

* **经典安全度不足**：BN254 经 Kim–Barbulescu 扩展 TNFS 攻击后，
  经典安全估计约 **100 bit**，低于 128 bit 现代基线（CNSA 2.0 等
  合规框架的门槛）。
* **不抗量子（质性失败）**：Groth16/配对曲线的离散对数假设对
  Shor 算法完全失效——这不是 100 对 128 的量差，而是 PQ 意义
  下的归零。本系统的签名核（XMSS）抗量子，但证明壳
  （BN254 Groth16）不抗量子，**PQ 叙事以下限为准**。

若部署场景要求 128 bit 经典安全或 PQ 完整性，必须替换证明系统
（如更高安全度曲线，或基于哈希的透明证明路线）。

## 已知性能边界

* `keygen` 在 `h = 10` 时约 30–60 秒（1M 次 Poseidon）。
  生产部署应：
  * 使用 `rayon` 并行化叶子循环（本 crate 未引入）。
  * 或使用超树（`d > 1`）减小单棵树高度。
* `benches/rsep.rs` 的 `sign` 基准在叶子耗尽后会 panic。
  生产基准应使用 `iter_batched`。

## 报告漏洞

见 `README.md` 的联系方式。请勿公开披露未修复的漏洞。
