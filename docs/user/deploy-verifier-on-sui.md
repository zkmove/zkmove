# Deploy an On-Chain Verifier on Sui

This guide deploys a verifier contract to a local SUI DevNet for the Fibonacci circuit (`example/fibonacci`).

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
sui client switch --address zkmove-local
sui client faucet --address zkmove-local --url http://127.0.0.1:9123/gas
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
# Path to the local verifier API Move package.
export VERIFIER_API_PACKAGE_DIR=/path/to/halo2-verifier.move/packages/api-sui

sui client --json -q test-publish \
  --build-env testnet \
  --skip-dependency-verification \
  --gas-budget 1000000000 \
  "$VERIFIER_API_PACKAGE_DIR"
```

Save the published package ID from the `published` object change of STDOUT:

```shell
export VERIFIER_API_PACKAGE=<published-package-id>
```

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

This produces JSON files whose Sui move-call arguments contain the artifact
bytes:

- `kzg_bn254_12-publish-params-native.txn`
- `test_fibonacci-1778483369682-publish-vk-native.txn`

Step 4 reads these descriptor files directly. Replace the witness filename with
the witness generated for your own circuit.

---

## 4. Upload the Artifacts as Sui Objects

Sui limits the size of pure `vector<u8>` arguments. Use the verifier API's
`artifact_builder` module to upload large artifacts in chunks. The repository
provides a wrapper script for the full flow. Run from the `halo2-verifier.move`
repository root:

```shell

scripts/upload_sui_artifacts.sh \
  --verifier-api-package "$VERIFIER_API_PACKAGE" \
  --artifacts-dir txns/sui-artifacts \
  --out-dir txns/sui-artifacts-upload
```

After the script finishes, it prints the finalized object IDs and writes them to
`txns/sui-artifacts-upload/sui-artifact-objects.env`:

```shell
PARAMS_OBJECT_ID=<serialized-params-object-id>
VK_OBJECT_ID=<serialized-vk-object-id>
```

Load them into your current shell:

```shell
source txns/sui-artifacts-upload/sui-artifact-objects.env
```
`PARAMS_OBJECT_ID` is a `SerializedParams` object. `VK_OBJECT_ID` is a
`SerializedVK` object that bundles both the Halo2 verifying key and the matching
zkMove circuit metadata. These object IDs are the Sui equivalent of the Aptos
params/verifier addresses used in the Aptos guide.
