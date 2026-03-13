# Deploy an On-Chain Verifier

This guide deploys a verifier contract to a local Aptos DevNet for the Fibonacci circuit (`example/fibonacci`).

---

## 1. Start the Local DevNet

Start a local Aptos network by following the official guide:
<https://aptos.dev/network/nodes/localnet/local-development-network#starting-a-local-network>

---

## 2. Create Account Profiles

Three separate accounts are needed:

| Profile | Purpose |
|---|---|
| `<contracts-profile>` | Publish shared verifier contracts |
| `<params-profile>` | Publish KZG parameters |
| `<verifier-profile>` | Publish per-circuit verifying key and circuit data |

> Separating `<params-profile>` from `<verifier-profile>` allows multiple circuits to share the same KZG parameters while each having its own verifier.

From the root of the `halo2-verifier.move` repository, run the following commands to create the profiles:

```shell
aptos init --profile <contracts-profile> --network local
aptos init --profile <params-profile>    --network local
aptos init --profile <verifier-profile>  --network local
```

Profiles are saved to `.aptos/config.yaml`. To check an account address:

```shell
aptos config show-profiles --profile <contracts-profile>
```

Fund each account via the faucet:

```shell
aptos account fund-with-faucet --url http://127.0.0.1:8080 --amount 5000000000000000000 --profile <contracts-profile>
aptos account fund-with-faucet --url http://127.0.0.1:8080 --amount 5000000000000000000 --profile <params-profile>
aptos account fund-with-faucet --url http://127.0.0.1:8080 --amount 5000000000000000000 --profile <verifier-profile>
```

---

## 3. Publish Verifier Contracts

Run the following script from the repository root to publish the shared verifier contracts:

```shell
PROFILE=<contracts-profile> ./publish_contracts.sh
```

---

## 4. Deploy the Circuit Verifier

Two verifier variants are available:

| Variant | Description |
|---|---|
| **Native** | Uses native functions for faster verification. |
| **Pure Move** | Implements verification entirely in Move; better portability. |

### Option A — Native Halo2 Verifier (Recommended)

**Step 1.** Publish the KZG parameters:

```shell
zkmove aptos build-publish-params-native-aptos-txn \
  --params-path example/params/kzg_bn254_12.srs \
  --params-contract-address <address-of-contracts-profile>
```

Submit the generated transaction to publish the KZG SRS under `<params-profile>`:

```shell
aptos move run --json-file kzg_bn254_12-publish-params-native.txn --profile <params-profile>
```

**Step 2.** Build and publish the verifying key and circuit data under `<verifier-profile>`:

```shell
# `-p` specifies the path to the circuit package (must contain a Move.toml file).
zkmove aptos build-publish-circuit-native-aptos-txn \
  --params-path example/params/kzg_bn254_12.srs \
  -p example \
  --circuit-name fibonacci \
  -w example/witnesses/test_fibonacci-1747793629098.json \
  --native-verifier-contract-address <address-of-contracts-profile>
```

This generates two transaction files:

- `test_fibonacci-1747793629098-publish-vk-native.txn`
- `test_fibonacci-1747793629098-publish-circuit-native.txn`

Submit them in order:

```shell
aptos move run --json-file test_fibonacci-1747793629098-publish-vk-native.txn      --profile <verifier-profile>
aptos move run --json-file test_fibonacci-1747793629098-publish-circuit-native.txn --profile <verifier-profile>
```

---

### Option B — Pure Move Verifier (Optional)

**Step 1.** Build and publish the KZG parameters:

```shell
zkmove aptos build-publish-params-aptos-txn \
  --params-path example/params/kzg_bn254_12.srs \
  --params-contract-address <address-of-contracts-profile>
```

Submit the generated transaction:

```shell
aptos move run --json-file kzg_bn254_12-publish-params.txn --profile <params-profile>
```

**Step 2.** Build and publish the circuit:

```shell
zkmove aptos build-publish-circuit-aptos-txn \
  --params-path example/params/kzg_bn254_12.srs \
  -p ./example \
  --circuit-name fibonacci \
  -w example/witnesses/test_fibonacci-1747793629098.json \
  --verifier-contract-address <address-of-contracts-profile>
```

Submit the generated transaction:

```shell
aptos move run --json-file test_fibonacci-1747793629098-publish-circuit.txn --profile <verifier-profile>
```
