# zkMove End-User SDK 实现方案

> 状态：初稿 / 待讨论
> 前置：[`sdk-roadmap.md`](./sdk-roadmap.md)（路线共识）、[`mvp-confidential-asset-mint.md`](./mvp-confidential-asset-mint.md)（MVP 已验证，W2–W6 + T6 全绿）
> 本文回答：MVP 之后，正式 SDK 怎么做。

---

## 1. 从 MVP 学到了什么（方案的出发点）

MVP 证明了三件事：端到端流程成立（witness→proof→分块→链上验证→mint）；强绑定成立（金额与证明密码学绑定，负测试确证）；"三个语义化调用 + 应用清单"的 SDK 形态成立（CLI 脚本与 GUI 共用同一接口）。

但 MVP 同时暴露了**产品缺口**——今天的"end user"实际需要一个完整开发环境：

| # | MVP 现状 | 对 end user 意味着 | SDK 必须解决 |
|---|---|---|---|
| G1 | witness 靠定制 `move` CLI + **电路源码包** + sandbox storage | 要装编译器、拿到 Move 源码、本地构建 | **拆分编译与执行**（评审修正，详见下）：编译归 app developer（离线，产物入 bundle）；运行期只读已编译模块执行取 witness——**core 不含 Move 编译器**，end user 不需要 move CLI / 源码 |
| G2 | proof 靠 `zkmove` CLI 读磁盘包 | 要装第二个 CLI | **消除**：prove 收进 core |
| G3 | 提交靠定制 `sui` client + 2 个 shell 脚本 + jq | 要装第三个 CLI、跑脚本 | **消除**：链上交互收进 SDK（Rust sui-sdk / TS sdk） |
| G4 | 一次 mint = 4+ 笔交易（builder/chunk×2/mint） | 多次确认、中途失败要恢复、无原子性 | **PTB 单笔交易**（见 §5 S3） |
| G5 | 密钥 = sui client keystore | 不是产品级钱包体验 | **demo 阶段不考虑**：沿用 MVP keystore，产品级钱包/密钥管理留待后续 |
| G6 | mint 语义硬编码在脚本里 | 换一个应用（transfer/burn/别的 app）要改代码 | **通用化**：应用清单 schema 驱动（§4） |
| G7 | 错误是 shell 退出码，进度是日志行 | 无法做 UI | 结构化错误 + 进度事件 |

**一句话定位**：SDK 的实现 = 把 MVP 的"开发者环境编排"产品化为"一个库 + 一份应用清单"。end user 的机器上最终只需要：**宿主应用（Tauri app 或浏览器页面）+ 应用清单 + 电路分发包**。

### G1 细化：编译（app developer，离线）vs witness 执行（运行期）

witness 的产生分两个**性质完全不同**的阶段，评审的要点是不要把它们混为一谈、更不要把整条塞进 prover core：

| 阶段 | 输入 | 工具 | 谁、何时做 | 产物 |
|---|---|---|---|---|
| ① **编译** | Move 源码（电路） | move-compiler（重） | **application developer，离线，一次** | 已编译模块 `.mv`（entry + 传递依赖） |
| ② **执行/取迹** | ①的 `.mv` + **end user 的私有实参** | move-vm-runtime（中） | 运行期，每次交易 | witness（`Footprints`，含执行轨迹） |

由此得到的边界：

- **编译完全归 app developer**：`zkmove bundle build` 内部 `move build`，把 `.mv` 模块打进 **bundle**（§3.2）。运行端**不存在** Move 源码，也不链接 move-compiler。
- **执行只读已编译模块**：运行期拿 bundle 里的 `.mv`（`move-binary-format` 反序列化为 `Vec<CompiledModule>`），用 move-vm-runtime 跑 entry，得 witness。这一步**不需要 move CLI、不需要源码、不需要 move-package**（包管理器是编译期/构建期的东西）。
- **"witness 不收进 prover core"**：witness 执行是一个**独立的轻组件**（`zkmove-witness`），与 `zkmove-core`（halo2 prover）平级，二者都只消费 bundle 的已编译模块（§3.1）。这样 prover core 保持纯净，也顺带让 core 的 wasm 路径更干净（不被 move-vm-runtime 拖累）。
- **end user 视角不变**：仍然不需要 move CLI / 源码 / 编译器——他要的"编译产物"已随 bundle 交付，本机只发生②的执行。

> 与上一版差异：上一版写"witness 收进 core"，把编译与执行糊在一起、且暗示 core 内嵌整条 move 工具链。本版按评审拆为"app dev 离线编译 + 运行期读已编译模块执行"，core 只做证明。

---

## 2. 角色契约（不变的边界）

```
zkmove          → 提供 SDK 本体 + verifier 链上设施（不进 SDK 的部署工具）
app developer   → 用 CLI 构建并发布: ①电路分发包(bundle) ②应用清单(manifest) ③应用合约
end user        → 通过 SDK: 本地算 witness/proof（秘密不出端）→ 提交带证明的应用交易 → 读结果
```

硬约束（继承 MVP）：**秘密绝不离开 end user 设备** → witness/prove 必须在客户端执行 → SDK 不能是服务端服务。

---

## 3. 总体架构（四层）

```
┌──────────────────────────────────────────────────────────────────┐
│ L3  应用编排层  @zkmove/sdk (TypeScript)                            │
│     ZkMove.load(manifest) / generateWitness / prove / submit / read│
│     Desktop 与 Browser 共用同一套 TS API（宿主不同，接口不变）        │
├──────────────────────────────────────────────────────────────────┤
│ L2  宿主层                                                         │
│     a) zkmove-sdk-desktop: Tauri v2 插件（commands+事件），内嵌 core │
│     b) (P3) @zkmove/prover-wasm: core 的 wasm 产物                  │
│     c) zkmove CLI: 改造为 core 的薄壳（开发者工具 + 回归基准）        │
├──────────────────────────────────────────────────────────────────┤
│ L1  链适配层（pluggable）                                           │
│     sui adapter: PTB 单笔提交（fallback: 多笔+断点续传）、对象读取、   │
│                  keystore；aptos adapter（后置，接口同形）            │
├──────────────────────────────────────────────────────────────────┤
│ L0  运行期 Rust 库（零 std::fs, bytes/JSON 进出；二者平级、都读 bundle 已编译模块）│
│   ┌ zkmove-witness（move-vm-runtime，无编译器/无 move-package）       │
│   │     execute_entry(modules, entry, args) -> Footprints           │
│   └ zkmove-core（halo2 prover）                                      │
│         prove / verify_local / poseidon_hash                        │
│         chunk_plan(bytes) -> {chunks, digest}                       │
│         tx payload builders（复用 sui/aptos-verifier-api 纯函数）    │
├──────────────────────────────────────────────────────────────────┤
│ L0.5 电路分发包 (circuit bundle) —— app dev 离线产物（含已编译 .mv）   │
│      witness 与 core 的共同输入格式                                  │
└──────────────────────────────────────────────────────────────────┘
   注：编译（源码→.mv）在 app developer 侧离线完成，不在本图任何运行期层。
```

### 3.1 L0：运行期 Rust 库（zkmove-witness + zkmove-core）

两个平级组件，都只消费 bundle 里的**已编译模块**（不碰源码、不碰编译器）。已验证的可行性依据：

- **witness 执行（`zkmove-witness`，与 prover core 解耦）**：`move sandbox run --witness` 的本体是 move-vm 的 `session.footprints()`（`move/third_party/move/tools/move-cli/src/sandbox/commands/run.rs:128`）。`zkmove-witness` 只 link `move-vm-runtime`，把 bundle 里的 `.mv` 反序列化后执行 entry 即得 `Footprints`——**不含 Move 编译器、不依赖 move-package**（编译已由 app developer 离线完成，见 G1 细化）。end user 不需要 move CLI / 源码。
  ⚠️ 评审修正：这对 encrypt 这类纯计算电路直接可行，但"与 sandbox 语义一致"不是免费的——bundle 必须显式定义 **VM 执行环境**：native function registry（如 `std::zkhash`）、gas 模式、module resolver、初始 storage/resources、signer 参数处理、bytecode version。这些进入 bundle 的 `vmEnv` 段（§3.2），P1.2 的验收覆盖正/负例矩阵（§5）。
- **prove 去 fs（`zkmove-core`）**：`VmCircuit::new` 对包的依赖只穿过 `StaticInfo::generate(entry, package, pubs)`（`vm-circuit/src/lib.rs:193`），后者只用编译后模块集合（`all_modules_map`/依赖遍历），不需要磁盘布局 → 新增 `StaticInfo::generate_from_modules(&[CompiledModule])` 即可绕开 `OnDiskCompiledPackage::from_path`，core 同样只吃 bundle 的已编译模块、不依赖 move-package。
- **payload 构造已是纯函数**：`sui_verifier_api::native_verifier::build_*` 返回 serde JSON（roadmap §3.2），直接复用。
- **分块器**：MVP 用 shell 脚本验证了协议（builder→append_chunk→finalize/digest）；core 只需输出 `{chunks[], digest}` 纯数据，发交易交给 L1。

API 表面（草案）：

```rust
// 全部 bytes/struct 进出，无路径、无 std::fs；编译产物（.mv）来自 bundle，运行期不编译

// —— zkmove-witness（仅 move-vm-runtime）——
pub fn load_bundle(bundle_bytes: &[u8]) -> Result<CircuitBundle>;   // 读已编译模块 + 元数据
pub fn execute_entry(bundle: &CircuitBundle, args: &[MoveValue]) -> Result<Footprints>;

// —— zkmove-core（halo2 prover）——
pub fn poseidon_hash(value: u128, nonce: u128) -> U256;
pub fn prove(bundle: &CircuitBundle, witness: &Footprints, srs: &[u8])
    -> Result<ProveOutput { proof, instance, k }>;
pub fn verify_local(bundle: &CircuitBundle, srs: &[u8], proof: &[u8], instance: &[u8]) -> Result<()>;
pub fn chunk_plan(bytes: &[u8], max_chunk: usize) -> ChunkPlan { chunks, digest };
pub fn build_sui_verify_payload(...) -> serde_json::Value;   // 复用 verifier-api
```

错误类型全部可序列化（`thiserror` + serde），供 GUI/TS 直接展示。wasm 兼容作为 P3 验收门槛（依赖图已知问题：`named-lock`/`whoami` 经 move-package 拖入——`generate_from_modules` 落地后 core 可以**不依赖 move-package**，这两个杀手随之消失，wasm gate 难度大幅下降）。

### 3.2 L0.5：电路分发包（circuit bundle）

新产品概念，**app developer 构建、end user 消费**，一次定义消除 G1/G2 的源码依赖：

```
bundle/
├── bundle.json          # 元数据（下）
├── modules/*.mv         # entry 模块 + 传递依赖（编译产物）
└── srs/kzg_bn254_12.srs # 可选内嵌；或 bundle.json 里给 URL+digest
```

```jsonc
// bundle.json（草案）
{
  "schema": "zkmove-bundle/1",
  "circuit": "encrypt",
  "entry": { "module": "0xCAFE::encryption", "function": "encrypt",
             "argTypes": ["u128", "u256", "u128"] },
  "config": { "maxExecutionRows": 4000, "maxPoseidonRows": 4000 },
  "pubsIndices": [1],
  "k": 12, "kzg": "gwc",
  "srs": { "embedded": "srs/kzg_bn254_12.srs", "sha256": "…" },

  // —— 一致性校验组（评审扩充：链上 SerializedVK 实际绑定 vk_bytes+circuit_bytes，
  //    proof 还依赖 params/SRS/k，单一 vkDigest 不足以对账）——
  "consistency": {
    "vkDigest": "…",           // 对账链上 SerializedVK.vk_digest
    "circuitInfoDigest": "…",  // 对账链上 SerializedVK.circuit_digest
    "paramsDigest": "…",       // 对账链上 SerializedParams.params_digest
    "nativeAbiVersion": 1      // native verifier ABI 版本（节点升级时 bump）
  },

  // —— VM 执行环境（评审新增：witness 生成语义的显式定义，见 §3.1 ⚠️）——
  "vmEnv": {
    "natives": "zkmove-std/1",   // native registry 标识（含 std::zkhash）
    "gas": "unmetered",
    "bytecodeVersion": 6,
    "initialStorage": "empty",   // empty | 内嵌 resources 快照
    "signers": []                // entry 的 signer 参数占位策略
  }
}
```

配套 CLI（app dev 工具，不进 SDK）：`zkmove bundle build -p <package> -c <circuit> -o bundle.zkb`，digest 组在 build 时计算填入。

**k 一致性（评审强调）**：当前 `mint_min` 合约硬编码 `k_present=false, k=0`（`mint_min.move:53`），意味着**只有 proof k == 链上 params k 才安全**。SDK 默认 **exact-k 强校验**（bundle.k 与链上 params 对账，不一致拒绝提交）；action schema 同时提供 `kPresent`/`kValue` 字段，供"合约接受 k 做 downsize"的应用声明传递（§4）。

### 3.3 L1：链适配层

- **sui adapter（先行）**：
  - **提交模式 A（目标，S3 = P2 blocker）**：PTB 单笔。⚠️ 评审修正后的精确表述：PTB 内的 builder **必须**来自 `public fun new_proof_builder` 的**命令返回值**（result chaining：`new_proof_builder → append_chunk×N → mint(builder,…)` 全在一笔内,创建即消费,天然原子）；**不能**用 `entry fun publish_proof_builder`（创建后 transfer 给 sender,同一 PTB 内拿不到可引用 object id——MVP 多笔流程用的正是后者,`upload_sui_proof.sh:387`）。两个入口在 `artifact_builder.move:86/:102` 均已存在,合约无需改动。S3 实测内容：result chaining 可行性、交易总大小/gas 上限、"多大 proof 必须 fallback"。**S3 不通过,P2 不得按模式 A 排期**。
  - **提交模式 B（fallback/大 proof）**：多笔交易（`publish_proof_builder` owned 对象路径,MVP 已验证）+ 断点续传（`runDir` 状态机持久化,重启可恢复）。
  - 实现载体：v0 沿用 sidecar 调 `sui client`（MVP 已验证）；v1 切 Rust `sui-sdk`（从 zkmove_sui fork 引）或 TS `@mysten/sui`（Browser 路径必然要做,Desktop 可复用——见 §6.3 Q3）。
- **aptos adapter（P3,评审决议）**：无 16KiB pure-arg 限制 ≠ 无限制——交易总大小/gas 上限仍需实测后再承诺直提,接口与 sui adapter 同形（`submit(action, args, proof)`）。

### 3.4 L2/L3：宿主与编排

- **zkmove-sdk-desktop**：把 MVP 的 3+2 命令插件化为 Tauri plugin crate,app dev 在自己的 Tauri 应用里 `tauri::Builder::plugin(zkmove_sdk::init())` 即接入;事件通道发进度(`witness:done`,`prove:progress`,`chunk:2/3`)。MVP 的 GUI 即第一个宿主样例。
- **@zkmove/sdk (TS)**：

```ts
// 高层:全清单驱动——派生/witness/交易参数的拼装规则都来自 manifest(§4),
// 调用方只供"用户输入",不写流程(评审修正:避免 poseidon/witness 顺序硬编码)
const sdk = await ZkMove.load(appManifest);
const r = await sdk.run("mint", { value, nonce }, { signer, onProgress });

// 低层:三步仍然单独可用(调试/自定义编排)
const enc = await sdk.poseidon(value, nonce);
const w   = await sdk.generateWitness("encrypt", [value, enc, nonce]);
const pf  = await sdk.prove("encrypt", w);
const r2  = await sdk.submit("mint", { encrypted_amount: enc }, pf, { signer });

const bal = await sdk.read("balance");            // 清单声明的只读查询
```

Desktop 实现走 Tauri invoke,Browser(P3)实现走 wasm——**同一份 TS 接口,两个后端**,正是 roadmap"一套 core,两个前脸"的 SDK 化。

---

## 4. 应用清单 schema v1（解决 G6 通用化）

MVP 清单只描述 mint;v1 把"应用有哪些动作、**每个动作的输入怎么派生、witness 怎么生成、交易怎么拼**"全部声明化。评审修正后,一个 action 分四段（`inputs / derived / witnessArgs / txArgs`）,缺一段"通用引擎"就会退化成 confidential-asset 专用逻辑:

```jsonc
{
  "schema": "zkmove-app/1",
  "app": { "package": "0x7e11…", "module": "mint_min" },
  "chain": { "type": "sui", "network": "localnet",
             "verifierApiPackage": "0x9a8b…",
             "paramsObjectId": "0xf416…", "vkObjectId": "0xba9d…" },
  "bundles": { "encrypt": "bundles/encrypt.zkb" },

  // —— 对象生命周期（评审新增:end user 的对象不是固定 id）——
  "objects": {
    "store": {
      "selector": { "ownedByUser": true,
                    "type": "{app.package}::mint_min::Store" },  // 按类型发现
      "init": "register",            // 不存在时执行的 initAction
      "pick": "single"               // single | promptUser(多个时让用户选)
    }
  },
  "initActions": {
    "register": { "function": "register", "args": [] }
  },

  "actions": {
    "mint": {
      "circuit": "encrypt",
      // ① 用户输入(秘密,只存在于本地)
      "inputs": { "value": "u128", "nonce": "u128" },
      // ② 派生值(受限内置函数集:poseidon/identity/…,见 D1 讨论)
      "derived": { "enc": { "fn": "poseidon", "args": ["value", "nonce"] } },
      // ③ witness 生成:电路 entry 的实参顺序(对应 bundle.entry.argTypes)
      "witnessArgs": ["value", "enc", "nonce"],
      // ④ 交易拼装
      "tx": {
        "function": "mint",
        "proof": { "inject": "builder",          // builder(分块) | pure(直传)
                   "kPresent": false },           // exact-k(默认);true 时需 kValue 来源
        "args": [                                 // 按合约签名顺序;source kind 显式化(评审修正)
          { "kind": "object",         "ref": "store" },
          { "kind": "object",         "ref": "params" },
          { "kind": "object",         "ref": "vk" },
          { "kind": "txResult",       "slot": "proofBuilder" },
          //   ↑ 模式A(PTB):同笔内 new_proof_builder 的命令返回值
          //     模式B(多笔):引擎自动降级为 ownedObject(publish_proof_builder 产物)
          { "kind": "computed",       "slot": "proofDigest" },
          { "kind": "const",          "value": 0, "type": "u8" },
          { "kind": "derived",        "ref": "enc", "type": "u256" }
        ]
      }
    },
    "transfer": { "...": "同形:circuit=check_sum(3 个 u256 公共输入),双 Store 对象,…" }
  },
  "reads": {
    "balance": { "object": { "ref": "store" }, "field": "balance" }
  }
}
```

要点（含评审修正）:

- **四段输入模型**:`inputs`(用户秘密)→`derived`(受限内置派生)→`witnessArgs`(电路实参)→`tx.args`(链上实参)。SDK 的 `run(action, inputs)` 据此通用执行,换 transfer/burn/其他 app 零代码。
- **参数来源 kind 显式化**:`object`(链上对象 id)/`txResult`(同 PTB 内前序命令返回值,**模式 A 的 builder 必须用它**)/`computed`(SDK 计算,如 digest)/`const`/`derived`/`input`。模式 A↔B 切换由引擎处理:A 用 `new_proof_builder` 返回值链式消费,B 降级为 `publish_proof_builder` 产出的 owned object id（两个合约入口都已存在,`artifact_builder.move:86/:102`）。
- **对象生命周期**:`objects.*.selector` 按类型发现用户 owned 对象,`init` 声明缺失时的创建动作,`pick` 处理多个;chain-id 校验失败（regenesis）给结构化错误。
- **k 传递**:`proof.kPresent=false`(默认)走 SDK exact-k 强校验;应用合约若接受 k 参数,声明 `kPresent:true` + `kValue` 来源。
- confidential-asset 的 mint/transfer/burn 作为 schema 验收用例（**check_sum 是 3 个 u256 公共输入**——评审勘误,正好作为 `pubsIndices` 多值+紧凑行映射的回归用例,即 Q6 决议）。

---

## 5. 实施阶段与验收

### P1：zkmove-core + bundle（地基,先行）

> 评审调序:**先定格式与语义,再写代码**——P1.0(bundle 格式 + vmEnv 规格)前置,否则 core API 返工。

| 任务 | 内容 | 验收 |
|---|---|---|
| **P1.0** | **bundle 格式（含已编译 `.mv` 布局）+ VM 执行环境规格定稿**（§3.2 schema 评审通过,含 consistency 组与 vmEnv 段;明确编译归 app dev 离线、运行期不编译） | schema 文档 + 评审签字;encrypt/check_sum/range_check 三电路能被格式描述 |
| P1.1 | `StaticInfo::generate_from_modules` + `CircuitBundle` 加载（从 bundle 已编译 `.mv` 反序列化，**不依赖 move-package**） | bundle(无源码) → `VmCircuit` 构建成功 |
| P1.2 | **`zkmove-witness` 独立组件**（与 prover core 平级）:link move-vm-runtime,`execute_entry` 读已编译模块执行,按 vmEnv 装配环境 | **不装 move CLI / 无源码 / 无编译器**,bundle+args → Footprints 与 CLI 产物逐字节一致;**测试矩阵（评审扩充）**:native `zkhash`(encrypt)、多模块依赖、signer 参数、storage 读写,各含正/负例 |
| P1.3 | prove/verify_local/poseidon/chunk_plan 去 fs 化 | encrypt 全流程内存进出;差分矩阵(pubs=[0]/[1]/[2]/[0,1,2]/无)全绿;**check_sum 3×u256 多公共输入回归**（Q6 决议） |
| P1.4 | `zkmove bundle build` 子命令 + CLI 改薄壳 + **顺手修 verify 空状态 vk 缺陷**（Q5 决议:verify 同走 bundle/witness 电路） | runbook 全流程用新 CLI 重放不回归;`verify --pubs-indices=1` 对合法 proof 通过 |
| P1.5 | 结构化错误 + serde | GUI 能展示分类错误 |

### P2：Desktop SDK v1（产品化）

| 任务 | 内容 | 验收 |
|---|---|---|
| P2.1 | 清单 schema v1 + 通用 action 引擎 | mint/transfer/burn 三动作零代码切换 |
| P2.2 | **S3 spike（P2 blocker）→ PTB 单笔提交** | 正路径:一笔交易完成 分块+verify+mint。**负路径矩阵（评审扩充）**:篡改 encrypted_amount、篡改 proof 字节、错 vk 对象、错 params 对象、错 chain-id、PTB 中间命令失败——每项都必须整笔原子回滚、给结构化错误、链上状态不变 |
| P2.3 | Tauri plugin 化 + 进度事件 | 第三方 Tauri app 三行接入;UI 实时进度 |
| ~~P2.4~~ | ~~密钥管理~~ **demo 阶段不做**（G5 决议）：沿用 MVP 的 sui keystore，仅保留一个 `Signer` 抽象接口位以便日后替换 | — |
| P2.5 | 断点续传(模式 B)+ runDir 状态机 | 杀进程后恢复上传;**runDir 不含任何 secret 级数据**（见下分级表） |
| P2.6 | e2e 自动化(runbook 脚本化,= W7) | CI 干净环境一键全绿 |

#### 本地敏感产物分级（评审新增,P2 横切要求）

"秘密不出端"必须延伸到**端内落盘策略**——witness 含私有实参（value/nonce 在 `Footprints.args` 里！）,MVP 把它明文写进 `witnesses/*.json` 和 runDir,这在 SDK 里不可接受:

| 数据 | 含密级 | 策略 |
|---|---|---|
| 用户输入(value/nonce) | **secret** | 仅内存;日志/错误信息**禁止**出现 |
| witness(Footprints) | **secret**(含 args) | 默认**不落盘**,prove 后即弃;dev 模式 opt-in 落盘并显式警告 |
| proof / instance | public(instance 即公共输入) | 可缓存于 runDir |
| 交易/链上 id/digest | public | runDir 留痕(可复现性来源) |
| run.log | — | 经 secret 过滤;`derived` 值(如 enc)属 public 可记 |

SDK 提供 `cleanup()`(删除 runDir)与自动过期策略(默认 N 天);断点续传状态机只依赖 public 级数据(proof 已生成才需要续传,witness 不参与)。

### P3：Browser（gate 后启动）

| 任务 | 内容 | 验收 |
|---|---|---|
| P3.1 | wasm gate 复验:core 去 move-package 后编 wasm32 | `cargo check --target wasm32` 过(named-lock/whoami 应已随依赖消失) |
| P3.2 | `@zkmove/prover-wasm`(wasm-bindgen,Worker,rayon+COOP/COEP) | 浏览器 prove encrypt,时延/内存达标(基准:native 600ms/75MB,目标 <5s) |
| P3.3 | `@mysten/sui` + dApp-kit 钱包接入 | 浏览器端完整 mint |
| P3.4 | SRS 加载(CDN+IndexedDB+digest 校验) | 弱网可用 |

### Spike 清单（P1 启动前/中并行,各 0.5–2 天）

- **S1** witness 收编可行性:core link move-vm 跑 encrypt,对照 CLI witness（P1.2 的前哨）
- **S2** `generate_from_modules`:确认 `all_modules_map`/依赖遍历可由模块列表重建（P1.1 前哨）
- **S3** **PTB 单笔提交**:`sui client ptb` 拼 builder+2chunk+mint,实测 gas/大小上限;顺带回答"多大 proof 必须 fallback 模式 B"
- **S4** sui Rust SDK from fork vs TS 提交路径(影响 Q3 决策)

---

## 6. 风险与开放问题

### 风险

| ID | 风险 | 缓解 |
|---|---|---|
| R1 | move-vm link 进 core 后,witnessing 语义与 sandbox 有隐性差异（gas/storage 初始化） | S1 用逐字节对照验收;保留 CLI 路径做 oracle |
| R2 | PTB 对 builder 对象 create+consume 同笔的支持面 | S3 早验;模式 B 永远在 |
| R3 | bundle/链上 vk 漂移（app dev 升级电路忘了重发 vk） | `vkDigest` 提交前强校验,错配直接拒绝 |
| R4 | 恶意/被篡改清单诱导用户给错误合约签名 | 清单含 `vkDigest`+合约地址,SDK 显示给用户确认;后续考虑清单签名 |
| R5 | wasm 性能仍未实测（roadmap R1 未关闭） | P3.2 设硬性达标线,不达标则 Browser 只做提交层 |
| R6 | 定制 sui fork 版本漂移（sui-sdk/链/合约三方对齐） | bundle/manifest 带 chain-id+版本;CI 钉 fork commit |

### 开放问题与决策记录（2026-06-12 评审）

| # | 问题 | 决策 |
|---|---|---|
| R4 | 清单信任模型 | **暂不考虑**（demo 阶段），保留在风险表备查 |
| Q4 | Aptos adapter 排期 | **P3** |
| Q5 | verify CLI empty-state vk 缺陷 | **P1.4 改薄壳时顺手修**（verify 同走 bundle/witness 电路） |
| Q6 | transfer/burn 多公共输入 | **采纳**：check_sum 三 u256 绑定作为 P1.3 回归用例 |
| Q1 | SRS 策略 | 待定，展开分析见 §6.3 |
| Q2 | 密钥管理深度 | **已决（G5）：demo 阶段不做**，沿用 MVP keystore + 留 `Signer` 接口位；§6.3 分析保留备查 |
| Q3 | Desktop 提交栈 | 待定，展开分析见 §6.3，S4 spike 供数 |

**第二轮评审采纳记录（2026-06-12）**：

| 评审意见 | 处理 |
|---|---|
| PTB 内 builder 必须用 `new_proof_builder` 返回值,非 `publish_proof_builder` 对象 id | ✅ 已核实合约两入口并存（`artifact_builder.move:86/:102`）;§3.3 改写,S3 升为 **P2 blocker**,schema 参数来源 kind 显式化 |
| witness 收编低估 sandbox 语义 | ✅ bundle 增加 `vmEnv` 段;P1.2 验收扩为 natives/多模块/signer/storage 正负例矩阵 |
| 一致性校验只有 vkDigest 不够 | ✅ bundle 增加 `consistency` 组（params/vk/circuitInfo digest + nativeAbiVersion）;exact-k 强校验默认,schema 留 `kPresent/kValue` |
| action schema 缺 witness 输入派生 | ✅ 四段模型 `inputs/derived/witnessArgs/tx.args`;派生函数机制（声明式 vs adapter）留为讨论项 D1 |
| end-user 对象生命周期未覆盖 | ✅ schema 增加 `objects.*.selector/init/pick` + `initActions` |
| 敏感产物留存策略缺失 | ✅ 新增分级表:witness 默认不落盘,runDir 仅 public 级,`cleanup()`+过期 |
| P1 顺序:先格式/语义后代码 | ✅ 新增 P1.0（bundle+vmEnv 规格定稿）前置 |
| P2.2 验收补负路径 | ✅ 六项负路径矩阵入验收 |
| check_sum 是 3 个公共输入（勘误） | ✅ 全文已订正 |
| Aptos 无 16KiB ≠ 无限制 | ✅ §3.3 注明交易大小/gas 仍需实测 |

**第三轮评审采纳记录（2026-06-12）**：

| 评审意见 | 处理 |
|---|---|
| G1 witness 不收进 core；编译归 app dev，运行期读已编译模块 | ✅ G1 改为"拆分编译与执行"+新增 G1 细化小节；架构 L0 拆为 `zkmove-witness`（move-vm-runtime，无编译器）与 `zkmove-core`（prover）平级；§3.1/API/P1.0–P1.2 同步 |
| G5 密钥 demo 阶段不考虑 | ✅ G5 改为"demo 不做"；P2.4 划掉只留 `Signer` 接口位；Q2 决议"demo 不做" |

#### Q1 SRS 策略（bundle 内嵌 vs URL+digest）

**上下文**：SRS（KZG structured reference string，如 `kzg_bn254_12.srs`）是 prover 的公共参数，end user 每次本地 prove 都要加载。两个关键性质：(a) **通用**——按曲线+k 区分而非按电路区分，k≤12 的所有电路共用同一份；(b) **体积随 k 指数增长**——k=12 ≈ 512KB，k=16 ≈ 8MB，k=20 ≈ 128MB。真实业务电路的 k 决定了这个问题的轻重。

**影响面**：
- *core API*：不受影响——`prove(bundle, witness, srs)` 已把 SRS 作为独立入参，解析（内嵌/下载/缓存）放在 L2 宿主层。
- *bundle schema*：字段形态（`embedded` path / `url`+`sha256`）现在定。
- *去重*：多应用/多电路共用同一 SRS；内嵌导致每个 bundle 重复携带，URL+本地缓存（desktop: app-data 目录；browser: IndexedDB）天然去重。
- *P3 浏览器*：必然走 URL+缓存（没人愿意 wasm 页面里捆 8MB），所以 URL 路径迟早要做。
- *离线*：内嵌可离线；URL 首次需网。
- *一致性*：无论哪种都必须 digest 校验 + 与链上 params 对象对账（错配的 SRS 只导致验证失败，不泄露秘密，风险是可用性而非机密性）。

**建议**：schema 两个字段都定义（至少其一必填），demo 阶段默认内嵌（k=12 才 512KB），P3 启动时实现 URL+缓存解析器。**这是个低风险问题，定默认值即可，不影响架构。**

#### Q2 密钥管理深度（**已决：demo 阶段不做，G5**；以下保留为日后产品化的背景分析）

**上下文**：密钥只在第⑦步出现——end user 给"proof 上传 + 应用调用"签名。MVP 用的是 sui client 的 keystore 文件（`~/.sui/sui_config/sui.keystore`，CLI 创建的明文格式），通过 sidecar `sui client call` 完成签名。这是开发者工具,不是产品。

**关键耦合**：密钥放哪里取决于**谁来构造和签名交易**（即 Q3）——
- Q3 选 sidecar sui client → 密钥**必须**在 sui keystore 文件里（CLI 只认它）；
- Q3 选 Rust sui-sdk → SDK 自己签名,密钥可由 SDK 管理（生成/导入/OS keychain 加密存储）；
- Q3 选 TS `@mysten/sui` → 密钥在 JS 侧（keypair 或将来 dApp-kit 钱包适配器）。

**影响面**：首次运行体验（"先去装 sui CLI 建地址" vs "应用内一键创建地址+领水"）；密钥安全（明文文件 vs keychain 加密;demo 阶段差异可接受）；浏览器路径（P3 必然交给钱包,SDK 不持钥——所以桌面密钥管理是桌面专属投入,不要过度建设）。

**建议**：深度上**保持浅**（demo 阶段）,但**接口上立刻定型**——SDK 对外暴露 `Signer` 抽象（TS: `signAndExecute(txBytes)` 回调;Rust: trait）,P2 的默认实现按 Q3 的结论选（keystore 文件读取 or JS keypair）,将来换 keychain/钱包不动调用方代码。**真正要现在定的是 Signer 接口,不是存储方案。**

#### Q3 Desktop 提交栈（影响最深的一个）

**上下文**：第⑦步在 SDK 里的实现载体。三个子任务:构造交易（PTB:builder+chunks+mint）、签名、提交并等待 effects。MVP 用 sidecar 定制 `sui client` + shell 脚本完成,SDK 要选正式形态:

| | A. sidecar sui client | B. Rust sui-sdk(fork) | C. TS `@mysten/sui` |
|---|---|---|---|
| 现状 | **已验证**(MVP 全程) | 未验证 | 未验证(S4) |
| 分发体积 | ❌ 要随应用带 sui 二进制(几十 MB) | ✅ 编进后端 | ✅ npm 依赖 |
| 版本漂移 | ✅ 零(client 即 fork) | ⚠️ 绑 fork commit,编译重 | ⚠️ 公版 SDK 需匹配节点协议版本 |
| 进度/错误 | ❌ 解析 stdout(已踩 u256 引号坑) | ✅ 类型化 | ✅ 类型化+事件 |
| 与 P3 浏览器复用 | ❌ 零复用 | ❌ 零复用 | ✅ **同一份提交代码** |
| 密钥(Q2) | keystore 文件 | SDK 管理 | JS keypair/钱包适配器 |
| PTB 单笔(G4) | `sui client ptb` 可拼但笨拙 | 原生支持 | 原生支持(`Transaction` API) |

**影响面**：这是 Q1–Q3 里**唯一影响架构的决策**——它决定 L1 适配层写在 Rust 侧还是 TS 侧、决定 Q2 的密钥归属、决定 P3 浏览器是"复用提交层"还是"重写提交层"、决定随应用分发什么。

**建议**：目标态选 **C**（TS 统一,Desktop/Browser 一份提交代码,与 dApp-kit 钱包生态对齐）;迁移期保留 A 作为已验证 fallback。唯一不确定点是公版 `@mysten/sui` 与我们 fork 节点（协议 1.72）的兼容窗口——**native 函数在节点里,RPC/交易格式是标准的,理论上无障碍,S4 spike 一天内可证**。若 S4 失败再退 B。

---

## 7. 与既有文档的关系

- 本文细化 roadmap 的 P0(a)/P1 为可执行任务;roadmap §12 的 wasm 阻塞结论由 P1（去 move-package）+P3.1 闭环。
- MVP 文档/runbook 保持为"流程证明"基线;P2.6 把 runbook 自动化为 CI。
- MVP 的 shell SDK/GUI 在 P2.3 完成前继续作为参考实现维护,之后退役为示例。
