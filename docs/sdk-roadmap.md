# zkMove SDK 路线图（初稿）

> 状态：初稿 / 待评审
> 范围：JS-SDK（WASM）与 Rust GUI（Tauri）两条交付路线的融合方案
> 关键决策（已确认）：
> - **Native verifier 优先**。Aptos 与 Sui 的 native 验证函数均在**我们自部署的节点**上支持，因此本路线第一阶段只覆盖 native 路径，Pure Move 路径暂不纳入交付范围（保留为兼容选项）。
> - 不做二选一：先抽**共享 Rust core**，短期用 **Tauri GUI** 交付完整流程，长期把同一套 core 编译成 **WASM** 做 JS SDK。

---

## 1. 背景与目标

当前 zkMove 的"从电路到链上验证"全流程横跨 **3 个定制 Rust 二进制** + 一套链上 Move 合约：

- 定制 `move` CLI（witnessing 分支）：编译 Move 包、执行 entry function、生成 witness。
- `zkmove` CLI（本仓 `cli/`）：生成 proof、本地验证、构造链上交易 payload。
- 定制 `aptos` / `sui` CLI：本地 DevNet、发布合约、签名并提交交易（节点内置 native 验证函数）。
- `halo2-verifier.move`：链上验证合约（Aptos / Sui 两套）。

目标：在不改变上述能力的前提下，为用户提供两种更易用的入口——
1. **JS-SDK（WASM）**：浏览器 / dApp 内完成证明与链上验证，零安装，可被第三方 npm 集成。
2. **Rust GUI（Tauri）**：桌面应用，向导式走完整流程，本机 native 证明，性能稳定。

两者共享同一个 **`zkmove-core`** Rust 库，避免逻辑双写。

---

## 2. 现有完整流程剖析（native 优先视角）

| # | 阶段 | 命令 / 入口 | 实际依赖 | 计算特征 |
|---|---|---|---|---|
| ① | 写电路 | 在 `Move.toml` 增加 `[circuit.<name>]`（声明 `entry`、`max_execution_rows`、`max_poseidon_rows`） | 纯文本 | 轻 |
| ② | 编译 + 发布 sandbox | `move build` / `move sandbox publish` | 定制 `move` CLI | 中（Move 编译器 + VM） |
| ③ | 生成 witness | `move sandbox run --witness …` | 定制 `move` CLI；运行后从 `session.footprints()` 写出 `witnesses/*.json`（见 `move/third_party/move/move-vm/runtime/src/interpreter/footprint.rs`、`.../session.rs`） | 中（VM 执行） |
| ④ | 生成 proof | `zkmove vm … prove -w witness.json` | `zkmove` CLI（`cli/src/vm_cmds.rs:27`）：读 SRS、编译产物、`Move.toml`、witness → 构造 `VmCircuit` → 算 `best_k` → 输出 `.proof` / `.instance` / `.vk` | **重（halo2 KZG 证明，CPU/内存密集）** |
| ④' | 本地验证（可选） | `zkmove vm … verify -k …` | `zkmove` CLI（同上）：`keygen_vk` 后 `verify_circuit` | 中 |
| ⑤ | 发布共享验证合约 | `publish_contracts.sh`（Aptos）/ `sui client publish api-sui`（Sui） | 定制链 CLI + 钱包/profile | 链交互 |
| ⑥ | 发布 params + circuit/vk | `zkmove aptos build-publish-*-native-aptos-txn` / `zkmove sui build-publish-*-native-txn` → 提交 | `zkmove` CLI 产 **JSON move-call 描述符**；提交由链 CLI / 标准 SDK 完成 | 轻（构造）+ 链交互 |
| ⑦ | 链上验证 proof | `zkmove aptos build-verify-proof-native-aptos-txn` / `zkmove sui build-verify-proof-native-txn` → 提交 | 同上；**Sui 需分块上传**（见 §3.3） | 轻 + 链交互 |

### 2.1 Native 路径在两条链上的差异

- **Aptos**：`build-publish-params-native-aptos-txn` → `kzg_…-publish-params-native.txn`；`build-publish-circuit-native-aptos-txn` → `…-publish-vk-native.txn` + `…-publish-circuit-native.txn`；`build-verify-proof-native-aptos-txn` → `…-verify-proof-native.txn`。每个 `.txn` 用 `aptos move run --json-file … --profile …` 提交。三类账户角色：`contracts`（共享合约）/ `params`（KZG 参数）/ `verifier`（每电路 vk + circuit data）。
- **Sui**：受 **pure `vector<u8>` 参数 16 KiB 上限**约束，params / vk / circuit_info / proof 都要走 **`artifact_builder` 分块上传状态机**（见 §3.3），不能把大字节直接当 pure 参数提交。验证最终只需 `PARAMS_OBJECT_ID` 与 `VK_OBJECT_ID`。

---

## 3. 关键技术事实（设计杠杆与约束）

> 这一节是所有设计决策的依据，务必先读。

### 3.1 杠杆：链上提交本质是"提交一份 JSON 描述符"

`zkmove` 的 `build-*-txn` 系列产出的是 **move-call 描述符**（`package / module / function / args / cli_args`）。提交是独立的一步。这意味着：

- **标准 JS 链 SDK（`@aptos-labs/ts-sdk`、`@mysten/sui`）可以直接消费该描述符并签名提交**，无需打包定制链 CLI。
- native 验证函数位于**节点**，不在提交方。由于**我们自部署的节点已内置 native 函数**，JS / GUI 向我们的节点提交 native 描述符即可工作。→ **native-first 在两条路线上都成立。**

### 3.2 杠杆：payload 构造函数已经是纯函数

CLI 外层虽然耦合文件系统，但真正干活的 payload 构造**已在独立 crate 中、以纯函数形式存在、返回 `serde_json::Value`**：

- Sui：`sui_verifier_api::native_verifier::{build_publish_params_native_transaction_payload, build_publish_vk_native_transaction_payload, build_verify_proof_native_transaction_payload}`（见 `cli/src/sui_cmds.rs:11`）。
- Aptos：`aptos-verifier-api` 对应的 native payload 构造函数（见 `cli/src/aptos_cmds.rs`）。
- 证明 / 验证：`halo2::proofs::{best_k, setup_circuit, prove_circuit, verify_circuit, KZG}`、`vm_circuit::{VmCircuit, CircuitGuard, public_inputs::PublicInputs}`、`halo2_verifier::{test_verifier, KZG}`。

→ **`zkmove-core` 抽取的工作量主要是"剥掉文件系统外壳"，而非重写算法。**

### 3.3 约束：Sui 分块上传是一个有状态子系统

链上合约 `halo2-verifier.move/packages/api-sui/sources/artifact_builder.move` 是一个多交易状态机：

```
new_params_builder / new_vk_builder / new_circuit_info_builder / new_proof_builder
        ↓ (多次)
append_chunk(builder, chunk)            // chunk ≤ max_chunk_bytes()
        ↓
finalize_params(builder, expected_digest)        → SerializedParams 对象
finalize_vk(vk_builder, circuit_builder, expected_vk_digest, expected_circuit_digest) → SerializedVK 对象
verify_proof_builder(params, vk, proof_builder, expected_proof_digest, public_inputs, kzg, k_present, k_value)
```

事实：`append_chunk`（`:106`）、`finalize_*`（`:119`/`:141`）、`verify_proof_builder`（entry，`:190`）均带 **digest 校验**；失败 abort（如 proof digest 匹配但验证失败 abort code `6`）。

→ **SDK / GUI 都必须把分块上传做成一等公民模块**，支持：分块、进度、重试、digest 校验、断点续传/恢复。不能只暴露一个 `buildVerifyTxn()`。现有 `halo2-verifier.move/scripts/upload_sui_artifacts.sh`、`upload_sui_proof.sh` 是参考实现。

### 3.4 约束：WASM 的真实拦路点

- **证明性能 / 内存（最大未知数）**：halo2 KZG 在 `wasm32` 默认单线程；多线程需 `wasm-bindgen-rayon` + 页面 **cross-origin isolation（COOP/COEP 响应头）**；`wasm32` 内存上限（~4GB，浏览器实际更紧），`k` 偏大易 OOM。证明应放 Web Worker 避免阻塞 UI。
- **编译产物加载**：`load_package` 走 `OnDiskCompiledPackage::from_path`（`cli/src/lib.rs:51`），**依赖磁盘目录布局**。WASM 无文件系统 → core 必须支持"从内存中的已编译包/字节"构造 `CompiledPackage`，这是 wasm 路径的关键改造点。
- **`CircuitGuard` 线程局部约束**：`VmCircuit` keygen/prove 期间必须持有 `CircuitGuard::new(circuit.clone())`（thread-local，见 `vm_cmds.rs:222`、`sui_cmds.rs:137`）。在 wasm + rayon 多线程下要确认 guard 的可见性与线程模型兼容。
- **SRS 体积**：`kzg_bn254_12.srs` 等数 MB～数十 MB，需 CDN 下载 + IndexedDB 缓存策略。

### 3.5 现有 `zkmove-wasm` 仅为过期 PoC

`/Users/ssyuan/work/project/zkmove-wasm` 是 `v0.3.0`，依赖老的 `young-rocks/move`，且代码注释明确写着 wasm 无法直接访问文件（`src/wasm.rs:185` 附近）。与当前 workspace（`vm-circuit` / `witness` / `movelang` + `zkmove/halo2` 系定制 crate）已分叉。→ **不可直接复用，需基于当前 core 重做 wasm 绑定**，并逐个验证 `wasm32-unknown-unknown` 可编译（已知坑：`getrandom` 的 `js` feature、`parking_lot_core` 版本钉死等，老仓 `Cargo.toml` 有踩坑痕迹可参考）。

---

## 4. 总体架构：一套 core，两个前脸

```
                         ┌─────────────────────────────┐
                         │         zkmove-core          │  纯 Rust 库
                         │  bytes/JSON 进出，零 std::fs  │
                         │  prove_from_artifacts        │
                         │  verify_local                │
                         │  build_aptos_*_payload (native)
                         │  build_sui_*_payload  (native)
                         │  sui chunk planner (digest)  │
                         └──────────────┬──────────────┘
                  ┌─────────────────────┼─────────────────────┐
                  ▼                                            ▼
   ┌──────────────────────────┐                ┌──────────────────────────────┐
   │  Tauri GUI (近期交付)     │                │  JS-SDK / WASM (长期生态)      │
   │  Rust backend #[command] │                │  wasm-bindgen + wasm-pack     │
   │  P0: 编排现有 CLI/脚本    │                │  @zkmove/prover-wasm          │
   │  P1: 直调 zkmove-core     │                │  @zkmove/sdk / aptos / sui    │
   │  钱包: CLI profile/脚本   │                │  钱包: Wallet Adapter/dApp-kit │
   └──────────────────────────┘                └──────────────────────────────┘
```

---

## 5. `zkmove-core` 设计（两条路线的共同底座）

### 5.1 设计原则

1. **零文件系统耦合**：所有输入输出用 `&[u8]` / `Vec<u8>` / serde struct，不接受路径、不调用 `std::fs`。文件读写留给各前脸（CLI、Tauri、JS host）。
2. **`wasm32-unknown-unknown` 可编译**：不引入 native-only 依赖；随机数走 `getrandom` 的 js feature；并行通过 feature gate（native = rayon，wasm = wasm-bindgen-rayon）。
3. **错误类型可序列化**：返回结构化错误，便于 JS / GUI 展示。

### 5.2 候选 API 表面（首版）

| 函数 | 输入（内存） | 输出 | 当前对应实现 |
|---|---|---|---|
| `parse_circuit_config(move_toml: &str, circuit_name: Option<&str>)` | Move.toml 字符串 | `CircuitConfigArgs` | `get_circuit_config_args_from_move_toml`（去掉 read_to_string） |
| `parse_entry_info(move_toml: &str, pkg: &CompiledPackage, circuit_name)` | 同上 + 内存包 | `EntryInfo` | `get_entry_info_from_move_toml`（去掉磁盘 `load_package`） |
| `load_package_from_bytes(...)` | 已编译包字节 | `CompiledPackage` | **新增**，绕开 `OnDiskCompiledPackage::from_path`（§3.4 关键改造） |
| `prove_from_artifacts(pkg, witness_bytes, srs_bytes, pubs_indices, kzg)` | 全内存 | `{ proof, instance, vk, k }` | `vm_cmds.rs` `ProveCommand::run` 去 fs 版 |
| `verify_local(pkg, srs_bytes, k, pubs_bytes, proof_bytes, kzg, circuit_cfg, entry)` | 全内存 | `Result<()>` | `VerifyCommand::run` 去 fs 版 |
| `test_native_verifier(pkg, witness, srs, pubs_indices, kzg)` | 全内存 | `{ serialized_params, vk_bytes, circuit_info_bytes, proof, public_inputs_bytes }` | `TestCommand::test_native_verifier` 去 fs 版 |
| `build_aptos_publish_params_native(srs, contracts_addr)` | 内存 | JSON 描述符 | 复用 `aptos-verifier-api` |
| `build_aptos_publish_circuit_native(srs, pkg, witness, circuit_name, contracts_addr, pubs_indices)` | 内存 | JSON（vk txn + circuit txn） | 复用 `aptos-verifier-api` |
| `build_aptos_verify_proof_native(pubs, proof, k, contracts_addr, params_addr, verifier_addr, kzg)` | 内存 | JSON 描述符 | 复用 `aptos-verifier-api` |
| `build_sui_publish_params_native(srs, api_pkg, params_store_id)` | 内存 | JSON 描述符 | `sui_verifier_api::…build_publish_params_native_transaction_payload` |
| `build_sui_publish_vk_native(vk, srs, circuit, api_pkg)` | 内存 | JSON 描述符 | `…build_publish_vk_native_transaction_payload` |
| `build_sui_verify_proof_native(proof, kzg, pubs, api_pkg, params_obj, vk_obj, k)` | 内存 | JSON 描述符 | `…build_verify_proof_native_transaction_payload` |
| `plan_sui_chunks(kind, bytes, max_chunk_bytes)` | 字节 + 上限 | `{ chunks: Vec<Vec<u8>>, digest }` | **新增**，§3.3 分块器核心，前端据此发交易 |

> 注：`Footprints`（witness）需新增 `from_bytes` / `from_reader`；`ParamsKZG::read` 已接受任意 `Read`，内存 `Cursor` 即可；`PublicInputs::from_bytes` 已是字节接口。

### 5.3 与现有 crate 的关系

- `zkmove-core` 依赖 `vm-circuit` / `witness` / `halo2`(third-party) / `halo2-verifier` / `aptos-verifier-api` / `sui-verifier-api`。
- `cli/` 重构为 `zkmove-core` 的薄壳（只做参数解析 + 文件读写 + 调 core），保证 CLI 行为不回归。
- Tauri backend、wasm 绑定各自再包一层。

---

## 6. 方案二：Rust GUI（Tauri）—— 近期交付

### 6.1 技术选型

- **Tauri v2** + React/Vite 前端（前端编排层与 JS-SDK 复用同一套 TS 逻辑）。
- Tauri v2 的 **sidecar（外部二进制）** 与 **capability/permission 模型** 正好匹配现有 `move` / `zkmove` / `aptos` / `sui` / `scripts` 工具链形态。

### 6.2 安全模型（硬要求）

- 后端只暴露**白名单命令**，**绝不开放任意 shell**。
- 外部二进制（move/aptos/sui）通过 sidecar 声明，参数由后端构造，不透传用户原始字符串。
- capability 文件精确授权文件系统/网络访问范围。

### 6.3 后端命令（`#[tauri::command]`）

| 命令 | 职责 | P0 实现 | P1 实现 |
|---|---|---|---|
| `check_env` | 检测 move/aptos/sui CLI、节点连通性、SRS 是否就位 | 探测二进制版本 | 同 |
| `scan_package` | 解析 `Move.toml`，列出 `[circuit.*]` 与 entry | 调 core `parse_*` | 同 |
| `generate_witness` | ②③ | sidecar 调 `move build` / `sandbox publish` / `sandbox run --witness` | 同（witness 生成短期仍依赖定制 move CLI） |
| `prove` | ④ | sidecar 调 `zkmove vm … prove` | 直调 `zkmove-core::prove_from_artifacts`（native，去二进制依赖） |
| `verify_local` | ④' | sidecar 调 `zkmove vm … verify` | 直调 core |
| `deploy_aptos` | ⑤⑥（native） | 调 `publish_contracts.sh` + `zkmove aptos build-*` + `aptos move run` | payload 走 core，提交走 sidecar/标准 SDK |
| `deploy_sui` | ⑤⑥（native，含分块） | 调 `api-sui publish` + `zkmove sui build-*` + `upload_sui_artifacts.sh` | core 分块器 + sidecar 提交，UI 展示进度 |
| `verify_onchain` | ⑦（native） | Aptos：`build-verify-proof-native` + 提交；Sui：`upload_sui_proof.sh` + `verify_proof_builder` | 同上，core 化 |

### 6.4 向导式 UX（wizard）

`环境检查 → 选择 package → 解析 circuits → 输入函数参数 → 生成 witness → 生成 proof → 本地 verify → 部署 verifier（params/vk/circuit）→ 链上 verify`

- **Sui 专属页**：分块上传进度条 + 重试/恢复（因为它本质是多交易状态机）。

### 6.5 可复现 run workspace

固定为 `.zkmove/runs/<timestamp>/`，记录：

- 每步执行的命令与参数、输入文件指纹、输出产物（proof/instance/vk/txn）、
- 链上结果：tx hash（Aptos）、object id（Sui：`PARAMS_OBJECT_ID` / `VK_OBJECT_ID` / `PROOF_BUILDER` / digest）。
- 目的：失败可查、可续传、可复现、可分享。

### 6.6 优缺点

- **优点**：最快覆盖完整流程；本地文件 / 编译产物 / witness / SRS / 定制 CLI / 本地 DevNet 天然可用；native 证明性能与内存稳定；可直接复用现有 docs 与 scripts。
- **缺点**：需安装桌面应用，发布要处理签名/公证/自动更新/跨平台打包；不是 npm SDK；长期依赖 sidecar 会有版本漂移与权限管理成本（P1 切 core 直调可缓解证明/payload 部分，witness 生成短期仍依赖定制 move CLI）。

---

## 7. 方案一：JS-SDK（WASM）—— 长期生态入口

### 7.1 范围控制（重要）

- **v1 不承诺"浏览器从 Move 源码到 witness 到 proof 全包"。** v1 输入由用户提供：`Move.toml` + 编译产物 + **witness JSON**（仍由本地定制 `move` CLI 生成）+ SRS params。浏览器负责 **④ proof / ④' 本地 verify / ⑥⑦ 构造 native 描述符 + 提交**。
- **据实标注 v1 定位**：v1 JS-SDK 本质是"**prover + native payload 构造 / 提交库**"，**不是**"零安装全流程入口"。原始愿景（浏览器端 deploy→verify→proof 全包）要到 **P2**（浏览器内 Move 编译 + VM 生成 witness）才成立。
- **v2 才研究**浏览器内 Move compiler + VM：需要虚拟文件系统、依赖锁定、禁用动态 git fetch，工作量明显更大（§3.4）。

### 7.2 包分层

| 包 | 职责 |
|---|---|
| `@zkmove/prover-wasm` | `zkmove-core` 的 wasm 产物（wasm-bindgen / wasm-pack `--target web`），导出 prove / verify / build payload / 分块器，附 TypeScript types |
| `@zkmove/sdk` | 编排层（与 Tauri 前端共用）：流程状态机、错误处理、SRS 加载/缓存 |
| `@zkmove/aptos` | 基于 `@aptos-labs/ts-sdk`，消费 native 描述符 → 钱包签名 → 提交我们的节点 |
| `@zkmove/sui` | 基于 `@mysten/sui`，**内建分块上传器**（进度 / 重试 / digest 校验 / 恢复），消费 native 描述符 + dApp-kit 钱包 |

### 7.3 关键工程项

- **wasm 工具链验证**：逐依赖确认 `wasm32-unknown-unknown` 可编译（getrandom js、parking_lot、rayon → wasm-bindgen-rayon）。
- **多线程证明**：`wasm-bindgen-rayon` + 页面 COOP/COEP（cross-origin isolation）+ Web Worker。
- **SRS 加载**：CDN 下载 + IndexedDB 缓存 + 进度提示。
- **CompiledPackage 内存加载**：依赖 core 的 `load_package_from_bytes`（§3.4）。
- **Sui 分块上传器（JS 侧）**：调 core `plan_sui_chunks` 得到 chunks + digest，再用 `@mysten/sui` 逐笔发 `append_chunk` / `finalize_*` / `verify_proof_builder`，全程进度/重试/恢复。

### 7.4 优缺点

- **优点**：无安装；适合 dApp / 钱包集成；易发布 npm；浏览器内出 proof 体验好；可被第三方组合。
- **缺点**：证明性能/内存是**最大未验证风险**（见 §8 gate）；当前 `zkmove-wasm` 仅过期 PoC；浏览器内 witness 生成、SRS 大文件、wasm 内存/线程、Sui 大 proof 上传均为主要风险点。

---

## 8. 对比表（已校正）

| 维度 | JS-SDK（WASM） | Tauri GUI |
|---|---|---|
| 完整流程交付速度 | 慢（尤其 witness 生成） | **快**（复用现有 CLI/脚本） |
| 用户安装成本 | **低**（一个 URL） | 中（桌面应用 + 签名公证） |
| 浏览器 / dApp 集成 | **强** | 弱 |
| 本地文件 / CLI / DevNet | 弱 | **强** |
| proof 性能稳定性 | **未验证 / 高风险**（须 §8 PoC gate 前置，给数据前不排正式工期） | **高**（native 同速） |
| native 提交（我们的节点） | 可（标准 ts-sdk 直提描述符） | 可（sidecar / 标准 SDK） |
| 复用现有资产 | 需重做 wasm 绑定 | **直接复用三个 CLI / 脚本** |
| 长期生态价值 | **高** | 中 |
| 工程风险 | 高 | 中低 |

> 注：上一版把 JS-SDK 的 proof 性能稳定性标"中"，自相矛盾。本版统一为"**未验证 / 高风险**"——在拿到目标电路规模的浏览器证明时延/内存数据前，**不允许给 JS-SDK 排正式交付工期**。

---

## 9. 风险登记（Risk Register）

| ID | 风险 | 影响 | 缓解 |
|---|---|---|---|
| R1 | WASM 证明在目标电路规模下时延/内存不可接受 | JS-SDK 路线可能证伪 | **P0 前置 PoC gate**（§10），拿到数据再决策 |
| R2 | `OnDiskCompiledPackage::from_path` 无法在 wasm 用 | 阻塞浏览器证明 | core 新增 `load_package_from_bytes`，优先验证 |
| R3 | `CircuitGuard` thread-local 与 wasm+rayon 线程模型冲突 | 证明出错/不可并行 | PoC 阶段验证 guard 可见性 |
| R4 | Sui 分块上传中途失败无法恢复 | 链上验证不可靠 | core 分块器输出 digest；前端做断点续传 + run workspace 留痕 |
| R5 | 定制依赖（zkmove/halo2 等 git crate）wasm 不可编译 | 阻塞 wasm | PoC 阶段逐依赖排查，必要时打 patch |
| R6 | witness 生成短期仍依赖本地定制 `move` CLI | "零安装"愿景 v1 不成立 | 据实沟通预期；P2 再做浏览器内 witness |
| R7 | Tauri 跨平台打包 + macOS 签名公证成本 | 发布延期 | 早建三平台 CI；MVP 先内部分发 |
| R8 | SRS 文件体积影响首屏 | JS 体验 | CDN + IndexedDB 缓存 + 进度 |

---

## 10. 分阶段路线图（native-first）

### P0（并行启动）

- **(a) 抽 `zkmove-core`**：bytes/JSON 进出，零 `std::fs`；先服务最苛刻消费者（wasm），由其定义 API 边界。交付 §5.2 表中函数 + CLI 改薄壳（行为不回归）。
- **(b) WASM 证明 PoC（go/no-go gate）**：基于当前 `vm-circuit` 重做最小 wasm 绑定，实测**目标电路 `k` 下**的浏览器证明时延与峰值内存；验证 R2/R3/R5。**输出一页数据报告决定 JS-SDK 是否全量投入。**
- **(c) Tauri-套-CLI MVP**：v2 + sidecar 编排现有 `move`/`zkmove`/`aptos`/`sui`/`scripts`，命令白名单，wizard（§6.4），`.zkmove/runs/<ts>` 留痕。**不依赖 (a) 即可先出 UI/UX。**

### P1

- Tauri 后端的 prove / verify / payload 切到 **`zkmove-core` 直调**（去掉对 `zkmove` 二进制的依赖；witness 仍走定制 move CLI）。
- JS spike（受 (b) gate 通过约束）：覆盖"**已有 witness + 编译产物 → proof / 本地 verify / 构造 native 描述符 → 提交我们的节点**"。
- **Sui 分块上传器**：core `plan_sui_chunks` + 前端（GUI 与 JS 各一套，逻辑共享 TS 编排）实现进度/重试/digest/恢复。
- JS 包分层 `@zkmove/{prover-wasm, sdk, aptos, sui}` 成形。

### P2（仅当 R1 gate 通过且性能可接受）

- 浏览器内 Move 编译 + VM 生成 witness（虚拟文件系统、依赖锁定、禁动态 git fetch）→ 真正"零安装全流程" JS-SDK。
- 视需要再评估 Pure Move verifier 路径（当前不在范围）。

---

## 11. 待确认 / 决策记录

| 项 | 状态 |
|---|---|
| 目标部署链是否内置 native 函数 | **已确认**：Aptos + Sui 均在我们自部署节点上支持 native → 本路线 native-first |
| 是否做二选一 | **否**：共享 core，Tauri 近期 + JS 长期 |
| Pure Move verifier 路径 | 暂不纳入交付范围（保留兼容） |
| v1 JS-SDK 是否含浏览器内 witness 生成 | **否**（推迟到 P2） |
| WASM 证明性能 | **已部分验证**（见 §12）：native 基线 fibonacci k=9 ≈ 600ms / 75MB；**但当前 `vm-circuit` 编不过 wasm32**（move-package → named-lock/whoami），须先做 core 解耦才能拿浏览器数字 |
| 目标电路规模（用于 PoC 基准） | **待补**：需产品/研发给出代表性电路（dark-forest / confidential-asset）与 `k` 范围 |

---

## 12. 附录：快速验证结果（2026-06-09）

目标：为方案一（WASM）的性能风险拿一个真实数据点。结论分两部分——**native 基线（拿到真实数字）** 与 **WASM 可编译性（发现硬阻塞）**。

### 12.1 老 `zkmove-wasm` 无法直接复用（已实证）

- 老 PoC 的 5 个 path 依赖（`error`/`logger`/`movelang`/`vm`/`vm-circuit`）中 **4 个已不在当前 `zkmove-vm`**；连"已迁到 `/Users/ssyuan/work/project/move`"的说法也不成立——move 仓（commit `f98f7d6`）只含 Move 语言工具链 + `move-prover`（形式化验证），搜不到 `compile_source_files`/`StateStore`/`proof_vm_circuit_kzg`/`VmCircuit` 等符号。真正迁到 move 的是 **witnessing/footprint**（`move-vm/runtime/src/interpreter/footprint.rs`，流程第③步），不是证明 VM。
- 老 PoC 即使复活，用的是 PSE `halo2 v0.3.0` + 硬编码 5 条字节码玩具脚本，**不代表当前栈**。故放弃，改测当前栈。

### 12.2 Native 证明基线（真实数字，当前栈）

机器：Mac17,2（M 系，10 核 / 32GB / macOS 26）。电路：`example/fibonacci`（`max_execution_rows=278, max_poseidon_rows=100`）。命令：`zkmove vm … prove`（release 构建），跑 3 次。

| 指标 | 值 |
|---|---|
| 最优 k | **9**（2^9 = 512 行） |
| 纯证明时间（`prove_circuit`） | **~600 ms**（598 / 620 / 601 ms） |
| 整进程耗时（含读 SRS/包/witness + vk/pk keygen + IO） | 0.78 – 1.8 s |
| 峰值内存（maximum RSS） | **~75 MB** |
| proof 大小 | 24.8 KB |
| 并行度 | `user 3.06s / real 0.78s` → **native halo2 启用 rayon 多线程（~4 核有效）** |

WASM 外推（基于上表）：单线程 WASM 失去 ~4 核并行 + 2–4× 计算惩罚 → 这颗玩具电路约 **6–12 s**；多线程 WASM（`wasm-bindgen-rayon`+COOP/COEP）约 **2–5 s**。**注意**：fibonacci k=9 是玩具，真实电路 k 每 +1 时间/内存约翻倍，k=15 即 ~64×，单线程 WASM 可能数分钟且内存逼近 wasm32（~2–4GB）上限。

### 12.3 WASM 可编译性：当前 `vm-circuit` 编不过 wasm32（硬阻塞，已实证）

`cargo check -p vm-circuit --target wasm32-unknown-unknown` 逐层暴露：

| 层 | 阻塞 | 性质 | 修复 |
|---|---|---|---|
| 1 | `getrandom v0.2` 需 `js` feature | 轻 | 一行依赖（已验证可越过） |
| 2 | `named-lock v0.2.0` 无 wasm 实现（`RawNamedLock`/`NameType` 缺失） | 中 | 需 patch/stub 或剥离 |
| 2 | `whoami` 无 wasm | 中 | 同上 |

依赖链（`cargo tree -i`）：

```
vm-circuit ─┐
witness  ───┴─> move-package (zkmove/move f98f7d6) ─┬─> named-lock v0.2.0  (无 wasm)
                                                     ├─> whoami            (无 wasm)
                                                     └─> walkdir           (fs 遍历)
```

**好消息**：依赖里**没有** git2 / libgit2 / reqwest / openssl / tokio，wasm 杀手集合比预想小。
**根因**：当前 `vm-circuit::new` / `witness` 在**类型层面**绑死 `move-package` 的 `CompiledPackage`，把整个包管理器（`named-lock`/`whoami`/`walkdir`）拖进 wasm 构建图。这正是 §3.4 / §5 / R2 / R5 所指。

### 12.4 验证结论

1. **方案一拿不到"浏览器真实证明数字"的前提，是先完成 `zkmove-core` 解耦**——把 `vm-circuit` 的证明路径从 `move-package` 上摘下来（接受内存中的 `CompiledModule` 而非磁盘 `CompiledPackage`），并 patch/stub `named-lock`+`whoami`。这是 §5 `load_package_from_bytes` 与"零 std::fs"原则的硬性前置，**不是一行修复**。
2. **native 性能本身不是瓶颈**（小电路 600ms / 75MB，且天然多线程）。方案二（Tauri，native）无此风险，**进一步支持"Tauri 先行"**。
3. 路线图据此更新：**P0(b) PoC 的第一步从"写 wasm 绑定"前移为"vm-circuit 去 move-package 耦合 + 过 wasm32 编译"**；编译通过后才谈得上浏览器证明计时。
4. 仍**待产品/研发补**：代表性真实电路（dark-forest / confidential-asset）的 `k` 范围——玩具电路给不出方案一的真实风险量级。

> 复现命令：`cargo build --release -p zkmove-cli`；`/usr/bin/time -l target/release/zkmove vm --params-path <srs> --package-path <halo2-verifier.move/example> --circuit-name fibonacci prove -w <witness.json>`。wasm 验证：`rustup target add wasm32-unknown-unknown && cargo check -p vm-circuit --target wasm32-unknown-unknown`。

---

*本文件为初稿，落盘于 `zkmove-vm/docs/sdk-roadmap.md`，供评审与迭代。*
