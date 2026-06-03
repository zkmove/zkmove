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

If the proof uses a non-default KZG opening scheme, pass it explicitly:

```shell
--kzg shplonk
```

If the proof and verifier key were generated after downsizing the KZG params,
pass the same `k` that you used for local verification. For the Fibonacci
example above, the circuit uses `k = 9`, while the source SRS file is
`kzg_bn254_12.srs`; the verify call must include `--k 9` so the native verifier
downsizes the published params before checking the proof:

```shell
--k <your_parameter_k>
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

Extract the BCS public inputs and proof bytes from the generated JSON:

```shell
VERIFY_TXN=txns/sui-verify/test_fibonacci-1778483369682-verify-proof-native.txn

json_byte_arg_hex() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    payload = json.load(f)
print(bytes(payload["args"][int(sys.argv[2])]).hex())
PY
}

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

export PUBLIC_INPUTS_JSON=$(jq -c '.args[2]' "$VERIFY_TXN")
export PROOF_HEX=$(json_byte_arg_hex "$VERIFY_TXN" 3)
export PROOF_DIGEST=$(hex_digest_json_array "$PROOF_HEX")
export KZG_VARIANT=$(jq -r '.args[4]' "$VERIFY_TXN")
export K_PRESENT=$(jq -r '.args[5]' "$VERIFY_TXN")
export K_VALUE=$(jq -r '.args[6]' "$VERIFY_TXN")
```

Create a proof builder object:

```shell
sui client --json -q call \
  --package $VERIFIER_API_PACKAGE \
  --module artifact_builder \
  --function publish_proof_builder \
  --gas-budget 1000000000
```

Save the created `ArtifactBuilder` object ID:

```shell
export PROOF_BUILDER=<proof-builder-object-id>
```

Append the proof chunks:

```shell
while IFS= read -r CHUNK; do
  sui client --json -q call \
    --package $VERIFIER_API_PACKAGE \
    --module artifact_builder \
    --function append_chunk \
    --gas-budget 1000000000 \
    --args $PROOF_BUILDER "$CHUNK"
done < <(hex_chunk_json_arrays "$PROOF_HEX")
```

---

## 3. Submit the Verification

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

## 4. Verify Through an Application Package

If your Sui app wraps proof verification and the proof may exceed 16 KiB, do
not expose `proof: vector<u8>` directly as an entry-function argument. Use the
same proof-builder pattern: upload the proof in chunks, then have the app entry
consume a proof builder or call a verifier API entry that consumes it.

Pass the same verifier objects:

```text
$PARAMS_OBJECT_ID
$VK_OBJECT_ID
```

The app should call:

```move
verifier_api::artifact_builder::verify_proof_from_builder(
    params,
    vk,
    proof_builder,
    expected_proof_digest,
    public_inputs_bcs,
    verifier_api::native_verifier::kzg_gwc(),
    k_present,
    k,
)
```

Use `kzg_shplonk()` and set `k_present` / `k` when those options match the
proof you generated. `public_inputs_bcs` is the same BCS-encoded public-input
byte array generated by `zkmove sui build-verify-proof-native-txn`.
