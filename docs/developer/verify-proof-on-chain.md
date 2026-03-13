# Verify a Proof On-Chain

This guide submits a proof-verification transaction to the local DevNet for the Fibonacci circuit.

**Prerequisites:** You have already generated a proof using the `zkmove` CLI and have the following output files:

- `example/proofs/test_fibonacci-1754384516414.instance`
- `example/proofs/test_fibonacci-1754384516414.proof`

---

## Option A — Native Halo2 Verifier

**Step 1.** Build the verify-proof transaction:

```shell
# Replace <your_parameter_k> with the actual `k` value used when generating the proof.
zkmove aptos build-verify-proof-native-aptos-txn \
  --pubs-path example/proofs/test_fibonacci-1754384516414.instance \
  --proof-path example/proofs/test_fibonacci-1754384516414.proof \
  --k <your_parameter_k> \
  --native-verifier-contract-address <address-of-contracts-profile> \
  --params-address <address-of-params-profile> \
  --native-verifier-address <address-of-verifier-profile>
```

**Step 2.** Submit the transaction. Any account can submit the verification:

```shell
aptos move run --json-file test_fibonacci-1747793629098-verify-proof-native.txn --profile <any-profile>
```

---

## Option B — Pure Move Verifier

**Step 1.** Build the verify-proof transaction:

```shell
zkmove aptos build-verify-proof-aptos-txn \
  --pubs-path example/proofs/test_fibonacci-1754384516414.instance \
  --proof-path example/proofs/test_fibonacci-1754384516414.proof \
  --verifier-contract-address <address-of-contracts-profile> \
  --params-address <address-of-params-profile> \
  --verifier-address <address-of-verifier-profile>
```

**Step 2.** Submit the transaction:

```shell
aptos move run --json-file test_fibonacci-1747793629098-verify-proof.txn --profile <any-profile>
```
