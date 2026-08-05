# Verify a Proof On-Chain

This guide submits a proof-verification transaction to the local DevNet for the Fibonacci circuit.

**Prerequisites:** You have already generated a proof using the `zkmove` CLI.
Select its output files before building a transaction:

```shell
export PROOF_PATH="$(find example/proofs -type f -name 'test_fibonacci-*.proof' -print | sort | tail -n 1)"
test -f "$PROOF_PATH"
export RUN_ID="$(basename "$PROOF_PATH" .proof)"
export PUBS_PATH="example/proofs/${RUN_ID}.instance"
test -f "$PUBS_PATH"
```

---

## Option A — Native Halo2 Verifier

**Step 1.** Build the verify-proof transaction:

```shell
export K_VALUE=$(jq -r .k example/setup/metadata.json)

zkmove aptos build-verify-proof-native-txn \
  --pubs-path "$PUBS_PATH" \
  --proof-path "$PROOF_PATH" \
  --k $K_VALUE \
  --native-verifier-contract-address <address-of-contracts-profile> \
  --params-address <address-of-params-profile> \
  --native-verifier-address <address-of-verifier-profile>
```

If `jq` is not available, replace `$K_VALUE` with the `k` value recorded in
`example/setup/metadata.json`.

**Step 2.** Submit the transaction. Any account can submit the verification:

```shell
aptos move run --json-file "${RUN_ID}-verify-proof-native.txn" --profile <any-profile>
```

---

## Option B — Pure Move Verifier

**Step 1.** Build the verify-proof transaction:

```shell
zkmove aptos build-verify-proof-aptos-txn \
  --pubs-path "$PUBS_PATH" \
  --proof-path "$PROOF_PATH" \
  --verifier-contract-address <address-of-contracts-profile> \
  --params-address <address-of-params-profile> \
  --verifier-address <address-of-verifier-profile>
```

**Step 2.** Submit the transaction:

```shell
aptos move run --json-file "${RUN_ID}-verify-proof.txn" --profile <any-profile>
```
