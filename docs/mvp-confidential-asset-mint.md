# MVP：Confidential-Asset `mint` 最小可跑流程（按角色，Sui localnet）

> 状态：v2（按评审意见收敛到最小可跑）
> 配套：[`sdk-roadmap.md`](./sdk-roadmap.md)
> 本版相对 v1 的收敛决策：
> 1. 应用入口不直接用完整 `token.move`，**参考它改一个最小版本**——mint 的本质就是"验证通过才能 mint token"。
> 2. SDK 先实现**最小版本，直接编排现有 CLI**，不等 `zkmove-core` 完整封装。
> 3. 落地形态**只做 GUI/Tauri**，浏览器/wasm 路线暂缓（见 roadmap §12 阻塞）。
> 4. proof 上链**直接走分块上传**（实测 proof≈29KB > Sui 16KiB pure-arg 上限，不再讨论直传）。
> 5. 验证**先用已测通的路径**（空公共输入，同 fibonacci Sui 流程），绕开 `--pubs-indices` 的 `BoundsFailure`（bug 并行修，修好后升级为绑定公共输入）。

---

## 0. 角色与 SDK 边界

### 0.1 三种角色

| 角色 | 是谁 | 在本例里做什么 |
|---|---|---|
| **zkmove** | 项目提供方 | 起 localnet；部署 `verifier_api`；发布 encrypt 电路的 params/vk 对象 |
| **application developer** | 用 zkMove 建应用的人 | 编译电路包；写并部署**最小 mint 合约**；发布"应用清单" |
| **end user** | 应用的终端用户 | 持有秘密（value+nonce）；本地生成 witness/proof；分块上传 proof 并调 mint |

### 0.2 步骤归属（对齐 roadmap §2）

| 步骤 | 归属 | 频次 | 进 SDK? |
|---|---|---|---|
| ① 写电路 / ② 编译发布 sandbox | application developer | 每电路一次 | ❌ CLI |
| ③ 生成 witness / ④ 生成 proof | **end user** | 每次 mint | ✅ |
| ⑤ 发布 verifier / ⑥ 发布 params+vk | zkmove | 每电路一次 | ❌ CLI |
| ⑦ 分块上传 proof + 调 mint | **end user** | 每次 mint | ✅ |

### 0.3 不可让步的约束

`encrypt(value, encrypted_value, nonce)` 证明"我知道 `value`/`nonce` 使 `zkhash(value,nonce)=encrypted_value`"。**end user 的秘密 `value`/`nonce` 绝不能离开本地** → witness/proof 必须在客户端生成 → SDK 不能做成服务端服务。

---

## 1. 最小实例

### 1.1 电路（已存在，不动）

`examples/confidential-asset/off-chain/sources/encryption.move` 的 `encrypt(value: u128, encrypted_value: u256, nonce: u128)`，电路声明 `[circuit.encrypt]`。

> MVP 注意：`prove` **不带 `--pubs-indices`**（见 §5.2）；同时建议补 `max_execution_rows`（v1 实测不补会 `BoundsFailure`，见 §5.2 缺陷 1）。

### 1.2 应用入口：最小 mint 合约（**新写**，参考 `on-chain-sui/token.move`）

完整 `token.move` 有 MintCap/inbox/transfer/burn 等，对 MVP 都是噪音。**mint 的本质 = 验证通过才能 mint token**。最小合约只保留：一个 `Store`、一个消费 `ProofBuilder` 的 mint 入口，验证直接复用**已测通**的 `artifact_builder::verify_proof_from_builder`（`public fun`，返回 `bool`，`packages/api-sui/sources/artifact_builder.move:168`）：

```move
module mint_min::mint_min;

use verifier_api::artifact_builder::{Self, ArtifactBuilder};
use verifier_api::native_verifier::SerializedVK;
use verifier_api::serialized_params_store::SerializedParams;

const EInvalidProof: u64 = 1;

public struct Store has key {
    id: UID,
    balance: u256,          // 加密余额（MVP：直接记录 encrypted_amount）
}

entry fun register(ctx: &mut TxContext) {
    transfer::transfer(Store { id: object::new(ctx), balance: 0 }, ctx.sender())
}

/// 验证通过才能 mint。proof 经 artifact_builder 分块上传后以 ProofBuilder 传入。
entry fun mint(
    store: &mut Store,
    params: &SerializedParams,
    vk: &SerializedVK,
    proof_builder: ArtifactBuilder,
    expected_proof_digest: vector<u8>,
    public_inputs: vector<u8>,     // BCS 字节；MVP 为空公共输入编码（来自 build-verify-proof 产物）
    kzg_variant: u8,
    encrypted_amount: u256,
) {
    assert!(
        artifact_builder::verify_proof_from_builder(
            params, vk, proof_builder, expected_proof_digest,
            public_inputs, kzg_variant,
            false, 0,              // k_present=false：proof 的 k 必须与发布 vk 时一致（§5.3）
        ),
        EInvalidProof,
    );
    store.balance = store.balance + encrypted_amount;   // MVP 简化：明文累加加密值占位
}
```

- 包结构：新建 `examples/confidential-asset/mint-min/`（`Move.toml` 依赖 `verifier-api = { local = ../../../halo2-verifier.move/packages/api-sui }`，地址绑定 localnet 上的 `VERIFIER_API_PACKAGE`）。
- ~~MVP 已知限制~~ **已升级为 v2 强绑定（2026-06-11）**：prover bug 修复后，合约改为链上现场构造 `public_inputs`（`push_u256(encrypted_amount)` + `sui::bcs::to_bytes`），`public_inputs` 参数从 `mint` 签名移除。链上验证的是"该 proof 恰好证明了这个 `encrypted_amount`"——金额与证明密码学绑定，已用负测试确证（合法 proof + 篡改金额 → abort）。流程结构（分块、对象、SDK 调用面）不变，仅 `mint` 少一个参数、清单 `pubsIndices=[1]`。

---

## 2. 角色推演（每条命令今天可执行）

### A. zkmove（一次性）

```bash
# A1 localnet（定制 sui）
sui start --force-regenesis --fullnode-rpc-port 9000 --with-faucet=127.0.0.1:9123
sui client new-env --alias localnet --rpc http://127.0.0.1:9000 && sui client switch --env localnet
sui client new-address ed25519 zkmove-local && sui client switch --address zkmove-local
sui client faucet --address zkmove-local --url http://127.0.0.1:9123/gas

# A2 部署 verifier_api → VERIFIER_API_PACKAGE
sui client --json -q test-publish --build-env testnet --skip-dependency-verification \
  --gas-budget 1000000000 /path/to/halo2-verifier.move/packages/api-sui

# A3 为 encrypt 电路发布 params/vk（分块）→ PARAMS_OBJECT_ID / VK_OBJECT_ID
#    注意：build vk 不带 --pubs-indices，与 §5.2 的证明路径保持一致
zkmove sui build-publish-params-native-txn --params-path <kzg_bn254_12.srs> \
  --verifier-api-package $VERIFIER_API_PACKAGE --output-dir txns/sui-artifacts
zkmove sui build-publish-circuit-native-txn --params-path <kzg_bn254_12.srs> \
  -p examples/confidential-asset/off-chain --circuit-name encrypt \
  -w <encrypt-witness.json> \
  --verifier-api-package $VERIFIER_API_PACKAGE --output-dir txns/sui-artifacts
scripts/upload_sui_artifacts.sh --verifier-api-package "$VERIFIER_API_PACKAGE" \
  --artifacts-dir txns/sui-artifacts --out-dir txns/sui-artifacts-upload
source txns/sui-artifacts-upload/sui-artifact-objects.env
```

### B. application developer（一次性）

```bash
# B1 ①② 编译电路包（end user 生成 witness 依赖此产物）
cd examples/confidential-asset/off-chain && move build && \
  move sandbox publish --skip-fetch-latest-git-deps --ignore-breaking-changes

# B2 部署最小 mint 合约（§1.2 新写）
cd ../mint-min && sui client publish --gas-budget 1000000000 .
export APP_PACKAGE=<mint_min-package-id>

# B3 建 Store
sui client call --package $APP_PACKAGE --module mint_min --function register --gas-budget 100000000
export STORE=<store-object-id>
```

**B4 应用清单**（交给 end-user SDK 的全部配置）：

```jsonc
{
  "chain": "sui-localnet",
  "appPackage": "<APP_PACKAGE>", "module": "mint_min", "function": "mint",
  "store": "<STORE>",
  "verifierApiPackage": "<VERIFIER_API_PACKAGE>",
  "paramsObjectId": "<PARAMS_OBJECT_ID>", "vkObjectId": "<VK_OBJECT_ID>",
  "circuit": {
    "packagePath": "examples/confidential-asset/off-chain",
    "name": "encrypt", "moduleStorage": "storage/0x...cafe/modules/encryption.mv",
    "entryFunction": "encrypt", "argTypes": ["u128", "u256", "u128"],
    "pubsIndices": [],          // MVP 空；T6 修复后改 [1]
    "kzg": "gwc", "k": 12, "srsPath": "<kzg_bn254_12.srs>"
  }
}
```

### C. end user（每次 mint，全程本地）

```bash
# C1 算加密值（zkhash = zkmove poseidon，与电路同算法同 domain）
zkmove poseidon --value 6 --nonce 0     # → encrypted_value

# C2 ③ witness（内置 zkmove vm run，不再需要定制 move CLI；实测 witness ≈ 10KB）
#    entry（module_id/function_name）从 Move.toml 的 [circuit.encrypt].entry 推导；
#    已编译模块由 run 自动灌入 storage/，无需先 move sandbox publish。
cd examples/confidential-asset/off-chain
zkmove vm --package-path . --circuit-name encrypt \
  run --args 6u128 <encrypted_value>u256 0u128

# C3 ④ proof（MVP 不带 --pubs-indices；实测 k=12，proof=29,472B）
#    注意：--params-path 已下沉到 prove 子命令
zkmove vm --package-path . --circuit-name encrypt \
  prove --params-path <srs> -w witnesses/encrypt-<ts>.json

# C4 ⑦ 构造 verify 数据 + 分块上传 proof + 调 mint
zkmove sui build-verify-proof-native-txn \
  --pubs-path proofs/encrypt-<ts>.instance --proof-path proofs/encrypt-<ts>.proof \
  --verifier-api-package $VERIFIER_API_PACKAGE \
  --params-object-id $PARAMS_OBJECT_ID --vk-object-id $VK_OBJECT_ID \
  --k 12 --output txns/sui-verify
scripts/upload_sui_proof.sh --verifier-api-package "$VERIFIER_API_PACKAGE" \
  --verify-txn txns/sui-verify/encrypt-<ts>-verify-proof-native.txn \
  --out-dir txns/sui-proof-upload
source txns/sui-proof-upload/sui-proof-builder.env   # PROOF_BUILDER / PROOF_DIGEST / PUBLIC_INPUTS_JSON / KZG_VARIANT

sui client --json -q call --package $APP_PACKAGE --module mint_min --function mint \
  --gas-budget 1000000000 \
  --args $STORE $PARAMS_OBJECT_ID $VK_OBJECT_ID $PROOF_BUILDER "$PROOF_DIGEST" \
         "$PUBLIC_INPUTS_JSON" $KZG_VARIANT <encrypted_value>
```

> C4 与文档已测通的 `verify_proof_builder` 流程**逐参数同构**，只是把最后一笔交易从通用验证入口换成 `mint_min::mint`。

---

## 3. 最小 SDK（不等 zkmove-core，直接编排 CLI）

形态：一个薄编排层（Tauri 后端 Rust `Command` 调用，或先用 shell/TS 脚本验证），**三个 end-user 语义化调用**，配置全部来自 B4 清单：

| 调用 | 封装内容 | 底层 |
|---|---|---|
| `computeEncrypted(value, nonce)` | C1 | `zkmove poseidon` |
| `proveMint(value, nonce)` | C1+C2+C3：witness → proof → 产出 `{encryptedValue, proofPath, instancePath}` | `zkmove vm run` + `zkmove vm prove` |
| `submitMint(encryptedValue, proofPath)` | C4：build-verify-txn → 分块上传（进度/重试）→ 调 `mint_min::mint` → 返回 digest | `zkmove sui build-verify-proof-native-txn` + `upload_sui_proof.sh` 逻辑 + `sui client call` |

- **分块上传器 MVP 版**：先直接复用/移植 `upload_sui_proof.sh` 的逻辑（new_proof_builder → append_chunk × N → 拿 digest），输出每块进度；重试 = 失败块重发；恢复（断点续传）放 V2。
- `zkmove-core` 仍是 P1 方向（roadmap §5），但**不阻塞本 MVP**。

---

## 4. 落地形态：只做 GUI / Tauri

| 步骤 | Tauri 实现 |
|---|---|
| ③ witness | sidecar 调 `zkmove vm run`（内置，不再需要定制 `move` CLI） |
| ④ proof | sidecar 调 `zkmove` CLI（native，<1s/75MB 量级，无性能风险） |
| ⑦ submit | sidecar 调 `sui` CLI（分块 + mint），UI 展示分块进度 |

- 命令白名单、参数由后端构造、`.zkmove/runs/<ts>` 留痕——沿用 roadmap §6 的安全与可复现要求。
- **浏览器/wasm 路线本 MVP 不做**（`vm-circuit` 编不过 wasm32，roadmap §12.3），等 core 解耦后另行立项。

---

## 5. 工程决策（已定，不再开放讨论）

### 5.1 proof 上链：**直接分块**

实测 encrypt proof = **29,472B（k=12）** > Sui 16KiB pure-arg 上限。一律走 `artifact_builder` 分块（`new_proof_builder → append_chunk → mint 内 verify_proof_from_builder` 消费）。不做直传分支。

### 5.2 验证路径：**先用已测通的（空公共输入），bug 并行修**

- 实测（2026-06-10）：`prove --pubs-indices=1`（绑定 u256 公共输入 `encrypted_value`）在 k=9/11/12 全部 `todo: BoundsFailure`（halo2_frontend `circuit.rs:329`）；同配置**去掉 pubs 则正常出证**。干净 A/B 对照 → prover 在绑定 u256 公共输入路径上的 bug。
- **根因（2026-06-11 已定位，差分实验确证）**：坐标系不一致——`PublicInputs::new`（`vm-circuit/src/public_inputs.rs:37`）把被绑定参数按 `pubs_indices` 顺序**从 instance 第 0 行起紧凑排列**；而电路装配（`vm-circuit/src/execution_circuit/executions/start.rs:366-384`）调 `assign_from_instance` 时用**函数签名参数下标 `arg_index` 当 instance 行号**。绑 arg1 时 instance 只有 1 行（row 0），电路查 row 1 → `query_instance` 越界 → `Error::BoundsFailure`（被 fork 中 `.expect("todo")` 吞为 panic）。与 u256 类型、k 值均无关。
- 差分实验（encrypt，同一 witness/k）：`pubs=[0]` ✅、`pubs=[2]` ❌、`pubs=[0,1,2]` ✅（行号恰好恒等映射）、`pubs=[1]` ❌——与假设完全一致。历史用例（fibonacci 等）从未暴露是因为都绑 arg 0。
- 链上侧约定与 `PublicInputs` 一致（`token.move::push_u256` 同样紧凑排列）→ **正确修法在电路侧**：`start.rs` 的 instance 行号应取 `arg_index` 在 `pubs_indices` 中的紧凑位置（多 ValueItem 参数需按前序被绑参数的行数累计偏移），而非 `arg_index` 本身。同时建议把 halo2 fork 中 `circuit.rs:329` 的 `.expect("todo")` 换成带上下文的错误传播。
- 隐患提示：若某被绑参数产生多行（vector/struct 等多 ValueItem），现行代码即使不越界也会**绑错行**——可能表现为验证失败而非 panic，修复时必须一并覆盖。
- 决策：**MVP 走无 pubs 的已测通路径**（与 fibonacci Sui 全流程一致），mint 流程先跑通；**T6 并行修 bug**，修复后清单 `pubsIndices` 改 `[1]`、合约 `public_inputs` 改为按 `encrypted_amount` 现场构造（token.move `push_u256` 模式），即升级为完整绑定。
- 附带缺陷：`[circuit.encrypt]` 原本不设 `max_execution_rows` 时 best_k 估小同样 `BoundsFailure`——app developer 在 B1 前补上（实测 `max_execution_rows=4000, max_poseidon_rows=4000` 下 k=12 可出证；最小值可再收）。

### 5.3 k / params 一致性

`mint` 内 `k_present=false`，链上不 downsize → **end user 证明用的 k 必须与 zkmove 发布 vk 时一致**（同一 SRS、同一电路配置）。清单固定 `k`，SDK 提交前校验。

---

## 6. 成功判据

1. end user 全程不暴露 `value`/`nonce`，仅以 `encrypted_value + proof` 完成 mint。
2. mint 后 `Store.balance` 更新，交易 `effects.status == success`。
3. 负路径：篡改 digest 或 proof 字节 → `mint` abort（`EInvalidProof` 或 builder digest 校验失败）。
4. 全流程在 Sui localnet 可由脚本一键复现。

---

## 7. Workrun 任务列表（按此顺序执行即可跑通）

| # | 任务 | 角色 | 具体内容 | 验收标准 | 依赖 | 状态 |
|---|---|---|---|---|---|---|
| W0 | 环境就绪 | 全部 | 定制 `sui`/`move`/`zkmove` + `jq` 在 PATH；`zkmove` release 已构建 | 四个二进制 `--version`/`-h` 正常 | — | ✅（本机已确认 move-cli 0.1.0、zkmove release、待确认 sui） |
| W1 | 电路配置修正 + 离线产物 | app dev | `[circuit.encrypt]` 补 `max_execution_rows`；`move build`；用 `zkmove poseidon` 算三元组、**`zkmove vm run` 出 witness**（内置，不再用定制 move CLI）、`prove`（无 pubs）出 proof | witness≈10KB、proof=29,472B（k=12）复现 | W0 | ✅ 2026-06-18：配置修正已提交（`max_execution_rows=4000`/`max_poseidon_rows=4000`）；witness 改走 `zkmove vm run`，off-chain 全链路在 feat/refactor 上复现（proof=29,472B/k=12 与历史一致） |
| W2 | localnet + verifier 基建 | zkmove | A1–A3：起链、发 `verifier_api`、为 encrypt 发布 params/vk（分块） | `sui-artifact-objects.env` 产出 `PARAMS_OBJECT_ID`/`VK_OBJECT_ID` | W0,W1(witness) | ✅ 2026-06-10：复用 `VERIFIER_API_PACKAGE=0x9a8b…6ded`（Pub.localnet.toml），新发 params=0x7646…f689 / vk=0x3819…69ac（k=12） |
| W3 | 最小 mint 合约 | app dev | 新建 `mint-min` 包（§1.2），publish，`register` 建 Store | 合约上链；错误 proof 调 `mint` 会 abort | W2 | ✅ `examples/confidential-asset/mint-min/`；`test-publish --pubfile-path Pub.localnet.toml` 解析已发布依赖；APP=0x56ed…0ad6，STORE=0x22a0…f7aa |
| W4 | 手工跑通 C 路径 | end user | C1–C4 逐条执行：proof 分块上传 → 调 `mint_min::mint` | §6 判据 1–3 全过 | W3 | ✅ 正路径 success、balance=encrypted_value；负路径（篡改 1 字节）abort code 1（EInvalidProof）、余额不变 |
| W5 | 最小 SDK（脚本版） | SDK | 把 C1–C4 收敛为 `compute-encrypted`/`prove-mint`/`submit-mint` 三个命令（shell 或 TS），读 B4 清单 | 一条命令完成一次 mint；分块有进度输出 | W4 | ✅ `examples/confidential-asset/sdk/zkmove-mint.sh` + `mint-min.manifest.json`；`mint 42 7` 一键全程 success，余额精确累加 |
| W6 | Tauri 壳 | SDK | W5 的三个命令包成 `#[tauri::command]`（sidecar 白名单），最小 wizard：输入 value/nonce → 一键 mint → 显示 digest/余额 | GUI 上完成一次 mint + 负路径提示 | W5 | ✅ 终验收通过：GUI 内完成 mint(100,12345)，tx `8XjiEM…dNvt` success，余额增量与 `encrypted(100,12345)` 精确一致 |
| W7 | e2e 一键脚本 | 全部 | 把 W2–W4 串成可复现脚本（A→B→C + 负路径断言），产物落 `.zkmove/runs/<ts>` | 干净环境一键全绿 | W4 | 待办 |
| T6 | （并行）修 prover bug + 升级绑定 | zkmove | 定位 `--pubs-indices` u256 公共输入 `BoundsFailure`；修复后：清单 `pubsIndices=[1]`、合约 `public_inputs` 现场构造 | `prove --pubs-indices=1` 出证；mint 校验 `encrypted_amount` 与证明绑定 | 独立并行 | ⚠️ **修复不在 main / feat/refactor 上**（2026-06-18 核实）：`start.rs:366-384` 仍用 `arg_index.into()` 当 instance 行号，`prove --pubs-indices 1` 仍 `BoundsFailure`。历史记录的 (a)–(d) 可能在某个未合并分支/工作树。**待办**：定位该分支 cherry-pick，否则按 §5.2 重写紧凑行映射。在此之前 demo 走空 pubs 弱路径（金额不强绑定） |

> 关键路径：W2 → W3 → W4 → W5 → W6；W1 已基本完成；T6 完全并行，修好即在 W3/W5 上做一次小升级（不改流程结构）。

---

*落盘于 `zkmove-vm/docs/mvp-confidential-asset-mint.md`，v2，供评审与执行。*
