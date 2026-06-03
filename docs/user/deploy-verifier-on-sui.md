# Deploy an On-Chain Verifier on Sui

This guide deploys the Sui verifier API package to a local Sui DevNet and publishes the reusable verifier artifacts needed by a zkMove circuit.

Sui uses objects instead of account resources, so the verifier artifacts are published as Sui objects:

| Object | Purpose |
|---|---|
| `SerializedParams` | Serialized KZG verifier parameters |
| `SerializedVK` | Serialized Halo2 verifying key plus the matching zkMove circuit metadata |

The circuit metadata is uploaded through a separate builder, but it is finalized together with the verifying key into one `SerializedVK` object. Verification later needs only `PARAMS_OBJECT_ID` and `VK_OBJECT_ID`.

---

## 1. Start the Local DevNet

Start a local Sui network with the customized `sui` CLI:

```shell
sui start \
  --force-regenesis \
  --fullnode-rpc-port 9000 \
  --with-faucet=127.0.0.1:9123
```

In another terminal, configure the client:

```shell
sui client new-env --alias localnet --rpc http://127.0.0.1:9000
sui client switch --env localnet
sui client new-address ed25519 zkmove-local
sui client switch --address <address>
sui client faucet --address <address> --url http://127.0.0.1:9123/gas
sui client balance
```

---

## 2. Publish the Verifier API Package

The Sui verifier API package lives in the `halo2-verifier.move` repository:

```text
halo2-verifier.move/packages/api-sui
```

Publish it to localnet. Use the `localnet` client environment for the target
chain, but build with the package's existing `testnet` build environment:

```shell
sui client switch --env localnet
export ZKMOVE_SUI_PUBFILE=/private/tmp/zkmove-sui-localnet.Pub.toml

sui client --json -q test-publish \
  --build-env testnet \
  --pubfile-path "$ZKMOVE_SUI_PUBFILE" \
  --skip-dependency-verification \
  --gas-budget 1000000000 \
  /path/to/halo2-verifier.move/packages/api-sui
```

Save the published package ID from the `published` object change:

```shell
export VERIFIER_API_PACKAGE=<published-package-id>
```

Do not use `--build-env localnet` for this package. `test-publish` publishes to
the current client network, so `--build-env testnet` still publishes to localnet
after `sui client switch --env localnet`. Keep the same `ZKMOVE_SUI_PUBFILE`
for later local app publishes so their `verifier_api` dependency resolves to
the package ID published above.

---

## 3. Build the Verifier Artifact Bytes

Use the Sui native transaction builders to produce the serialized byte blobs
needed by the on-chain verifier. In this step, the generated JSON files are
only used as artifact containers; do not submit these large pure-argument calls
directly if the artifacts exceed Sui's argument size limit. Step 4 uploads the
same bytes through the chunked `artifact_builder` flow.

Run from the `halo2-verifier.move` repository root:

```shell
mkdir -p txns/sui-artifacts

zkmove sui build-publish-params-native-txn \
  --params-path example/params/kzg_bn254_12.srs \
  --verifier-api-package $VERIFIER_API_PACKAGE \
  --output-dir txns/sui-artifacts

zkmove sui build-publish-circuit-native-txn \
  --params-path example/params/kzg_bn254_12.srs \
  -p example \
  --circuit-name fibonacci \
  -w example/witnesses/test_fibonacci-1778483369682.json \
  --verifier-api-package $VERIFIER_API_PACKAGE \
  --output-dir txns/sui-artifacts
```

Pass the verifier API package published in Step 2 so the generated Sui
move-call descriptors point at the same API package used later by proof
verification. The params-store arguments are omitted here because this guide
only extracts the serialized byte arrays from the generated JSON files; the
chunked upload in Step 4 uses the builder objects created on your Sui network.

If you intentionally want to submit the generated params publish call directly,
override those defaults with real values. In that direct path,
`--params-store-object-id` is the shared `SerializedParamsStore` object created
by calling `serialized_params_store::create_serialized_params_store`, and
`--publisher-address` is the address under which the params record is stored.
The chunked flow below does not use that direct params-store path.

This produces JSON files whose Sui move-call arguments contain the artifact
bytes:

- `kzg_bn254_12-publish-params-native.txn`
- `test_fibonacci-1778483369682-publish-vk-native.txn`

Extract the hex strings from the Sui JSON byte-array arguments:

```shell
json_byte_arg_hex() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    payload = json.load(f)
print(bytes(payload["args"][int(sys.argv[2])]).hex())
PY
}

export PARAMS_HEX=$(json_byte_arg_hex txns/sui-artifacts/kzg_bn254_12-publish-params-native.txn 2)
export VK_HEX=$(json_byte_arg_hex txns/sui-artifacts/test_fibonacci-1778483369682-publish-vk-native.txn 0)
export CIRCUIT_HEX=$(json_byte_arg_hex txns/sui-artifacts/test_fibonacci-1778483369682-publish-vk-native.txn 1)
```

Replace the witness filename with the witness generated for your own circuit.

---

## 4. Upload the Artifacts as Sui Objects

Sui limits the size of pure `vector<u8>` arguments. Use the verifier API's `artifact_builder` module to upload large artifacts in chunks.

The helpers below split hex blobs into 15 KiB JSON byte-array chunks and calculate the Blake2b-256 digest required by `finalize_*` calls:

```shell
hex_digest_json_array() {
  python3 - "$1" <<'PY'
import hashlib
import sys
digest = hashlib.blake2b(bytes.fromhex(sys.argv[1]), digest_size=32).digest()
print("[" + ",".join(str(b) for b in digest) + "]")
PY
}

hex_chunk_json_arrays() {
  python3 - "$1" <<'PY'
import sys
data = bytes.fromhex(sys.argv[1])
chunk_size = 15 * 1024
for offset in range(0, len(data), chunk_size):
    chunk = data[offset:offset + chunk_size]
    print("[" + ",".join(str(b) for b in chunk) + "]")
PY
}
```

Create one builder for params, one for the verifying key, and one temporary builder for circuit metadata:

```shell
sui client --json -q call \
  --package $VERIFIER_API_PACKAGE \
  --module artifact_builder \
  --function publish_params_builder \
  --gas-budget 1000000000

sui client --json -q call \
  --package $VERIFIER_API_PACKAGE \
  --module artifact_builder \
  --function publish_vk_builder \
  --gas-budget 1000000000

sui client --json -q call \
  --package $VERIFIER_API_PACKAGE \
  --module artifact_builder \
  --function publish_circuit_info_builder \
  --gas-budget 1000000000
```

Save the three created `ArtifactBuilder` object IDs:

```shell
export PARAMS_BUILDER=<params-builder-object-id>
export VK_BUILDER=<vk-builder-object-id>
export CIRCUIT_BUILDER=<circuit-builder-object-id>
```

Append chunks to each builder:

```shell
while IFS= read -r CHUNK; do
  sui client --json -q call \
    --package $VERIFIER_API_PACKAGE \
    --module artifact_builder \
    --function append_chunk \
    --gas-budget 1000000000 \
    --args $PARAMS_BUILDER "$CHUNK"
done < <(hex_chunk_json_arrays "$PARAMS_HEX")

while IFS= read -r CHUNK; do
  sui client --json -q call \
    --package $VERIFIER_API_PACKAGE \
    --module artifact_builder \
    --function append_chunk \
    --gas-budget 1000000000 \
    --args $VK_BUILDER "$CHUNK"
done < <(hex_chunk_json_arrays "$VK_HEX")

while IFS= read -r CHUNK; do
  sui client --json -q call \
    --package $VERIFIER_API_PACKAGE \
    --module artifact_builder \
    --function append_chunk \
    --gas-budget 1000000000 \
    --args $CIRCUIT_BUILDER "$CHUNK"
done < <(hex_chunk_json_arrays "$CIRCUIT_HEX")
```

Finalize the artifacts. Params become a `SerializedParams` object. The VK builder and circuit-info builder are consumed together to create one `SerializedVK` object:

```shell
sui client --json -q call \
  --package $VERIFIER_API_PACKAGE \
  --module artifact_builder \
  --function finalize_params_to_sender \
  --gas-budget 1000000000 \
  --args $PARAMS_BUILDER "$(hex_digest_json_array "$PARAMS_HEX")"

sui client --json -q call \
  --package $VERIFIER_API_PACKAGE \
  --module artifact_builder \
  --function finalize_vk_to_sender \
  --gas-budget 1000000000 \
  --args \
    $VK_BUILDER \
    $CIRCUIT_BUILDER \
    "$(hex_digest_json_array "$VK_HEX")" \
    "$(hex_digest_json_array "$CIRCUIT_HEX")"
```

Save the finalized object IDs:

```shell
export PARAMS_OBJECT_ID=<serialized-params-object-id>
export VK_OBJECT_ID=<serialized-vk-object-id>
```

These object IDs are the Sui equivalent of the Aptos params/verifier addresses used in the Aptos guide.

---

## 5. Optional: Publish an Application Package

If your Sui app calls the verifier from Move, add the verifier API dependency to the app's `Move.toml`:

```toml
[dependencies]
std = { git = "https://github.com/zkmove/sui.git", rev = "<sui-rev>", subdir = "crates/sui-framework/packages/move-stdlib" }
sui = { git = "https://github.com/zkmove/sui.git", rev = "<sui-rev>", subdir = "crates/sui-framework/packages/sui-framework" }
verifier_api = { git = "https://github.com/zkmove/halo2-verifier.move.git", rev = "<verifier-rev>", subdir = "packages/api-sui" }
```

Then publish the app package:

```shell
sui client --json -q test-publish \
  --build-env testnet \
  --pubfile-path "$ZKMOVE_SUI_PUBFILE" \
  --skip-dependency-verification \
  --gas-budget 1000000000 \
  /path/to/your/on-chain-sui-package
```

The app can now accept `&SerializedParams` and `&SerializedVK` objects and call `verifier_api::native_verifier::verify_proof`.
