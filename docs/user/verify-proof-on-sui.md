# Verify a Proof On-Chain on Sui

This guide builds and submits a proof-verification call to a local Sui DevNet.

The Sui path currently uses the native Halo2 KZG verifier included in the customized `sui` CLI. The `zkmove` CLI builds a Sui move-call descriptor, and `sui client call` submits it.

**Prerequisites:**

- You have generated a proof with `zkmove vm`.
- You have deployed the Sui verifier API package.
- You have published the verifier artifacts and saved:
  - `VERIFIER_API_PACKAGE`
  - `PARAMS_OBJECT_ID`
  - `VK_OBJECT_ID`

Example proof files:

- `example/proofs/test_fibonacci-1778483369682.instance`
- `example/proofs/test_fibonacci-1778483369682.proof`

---

## Install `jq`

This guide uses `jq` to inspect JSON transaction outputs from `sui client --json`.
Install it before submitting the verification call.

On macOS:

```shell
brew install jq
```

On Ubuntu or Debian:

```shell
sudo apt-get update
sudo apt-get install jq
```

Verify the installation:

```shell
jq --version
```

---

## 1. Build the Verify-Proof Data

Run from the `halo2-verifier.move` repository root. Replace the file names and object IDs with the values from your circuit and deployment:

```shell
mkdir -p txns/sui-verify

zkmove sui build-verify-proof-native-txn \
  --pubs-path example/proofs/test_fibonacci-1778483369682.instance \
  --proof-path example/proofs/test_fibonacci-1778483369682.proof \
  --verifier-api-package $VERIFIER_API_PACKAGE \
  --params-object-id $PARAMS_OBJECT_ID \
  --vk-object-id $VK_OBJECT_ID \
  --k 9 \
  --output txns/sui-verify
```

The command writes a file like:

```text
txns/sui-verify/test_fibonacci-1778483369682-verify-proof-native.txn
```

The file contains a JSON move-call descriptor with `package`, `module`,
`function`, `args`, and `cli_args`. For Sui, use this file as a data container:
the proof may be larger than Sui's 16 KiB pure-argument limit, so do not submit
this generated `native_verifier::verify` call directly unless you know the
proof argument is small enough.

---

## 2. Upload the Proof in Chunks

Sui limits the size of pure `vector<u8>` arguments. Use the verifier API's
`artifact_builder` module to upload the proof bytes in chunks. The
`halo2-verifier.move` repository provides a wrapper script for this flow. Run
from the `halo2-verifier.move` repository root:

```shell
scripts/upload_sui_proof.sh \
  --verifier-api-package "$VERIFIER_API_PACKAGE" \
  --verify-txn txns/sui-verify/test_fibonacci-1778483369682-verify-proof-native.txn \
  --out-dir txns/sui-proof-upload
```

After the script finishes, it prints `PROOF_BUILDER` and `PROOF_DIGEST`, and
writes all values needed by Step 3 to
`txns/sui-proof-upload/sui-proof-builder.env`.

---

## 3. Submit the Verification

Load the proof-builder values into your current shell:

```shell
source txns/sui-proof-upload/sui-proof-builder.env
```

Call `artifact_builder::verify_proof_builder`. This consumes the proof builder,
checks its digest, and verifies the proof without passing the whole proof as one
pure argument:

```shell
sui client --json -q call \
  --package $VERIFIER_API_PACKAGE \
  --module artifact_builder \
  --function verify_proof_builder \
  --gas-budget 1000000000 \
  --args \
    $PARAMS_OBJECT_ID \
    $VK_OBJECT_ID \
    $PROOF_BUILDER \
    "$PROOF_DIGEST" \
    "$PUBLIC_INPUTS_JSON" \
    $KZG_VARIANT \
    $K_PRESENT \
    $K_VALUE \
  > txns/sui-verify/verify-result.json
```

Any funded localnet account can submit the verification call.

Check that the transaction succeeded:

```shell
jq '.effects.status' txns/sui-verify/verify-result.json
```

A valid proof returns a successful transaction status. An invalid proof aborts
inside `verifier_api::artifact_builder::verify_proof_builder`.

If `jq` reports a parse error, inspect the file directly:

```shell
cat txns/sui-verify/verify-result.json
```

That usually means `sui client call` wrote a plain-text execution error instead
of JSON. An abort with code `6` from `artifact_builder::verify_proof_builder`
means the proof digest matched and the native verifier returned `false`. For
proofs generated from a downsized circuit, first check that the generated verify
txn has `.args[5] == true` and `.args[6]` set to the same `k` used when proving.

---
