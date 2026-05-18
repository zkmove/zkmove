#  Tutorial on zkMove CLI

This guide explains how to use `zkmove` CLI to create a circuit and generate a proof for it.

## Install customized `move` CLI

A customized Move CLI is required to generate witnesses. Install it with:

```shell
cargo install --git https://github.com/zkmove/move move-cli
```

## A zkMove Circuit example

To build zkmove circuits for a Move package, we need additional configuration in `Move.toml`. In this example, we create two circuits: `fibonacci` and `zkhash_example`.

```toml
[package]
name = "example"
version = "0.0.1"

[dependencies]
MoveStdlib = { git = "https://github.com/zkmove/move.git", subdir = "third_party/move/move-stdlib", rev = "main" }

[addresses]
std = "0x1"

#TODO: add more comments to explain the circuit options.
[circuit.fibonacci]
max_execution_rows = 278     # Max rows for the execution subcircuit.
max_poseidon_rows = 100      # Max rows for the poseidon subcircuit.
entry = { module_id = "0x1::fibonacci", function_name = "test_fibonacci" }

[circuit.zkhash_example]
max_poseidon_rows = 100
entry = { module_id = "0x1::zkhash_example", function_name = "hash" }
```

## Generate witness

First, build and publish the example package.

```shell
# Run under package root.
move build
move sandbox publish --skip-fetch-latest-git-deps --ignore-breaking-changes
```
Then generate the witness by executing the entry function. By default, witnesses are written to `witnesses/`.

```shell
move sandbox run --skip-fetch-latest-git-deps --witness storage/0x0000000000000000000000000000000000000000000000000000000000000001/modules/fibonacci.mv test_fibonacci --args 10u64
```

## Generate the proof

```shell
# Running in the package root. Replace the witness filename as needed.
cargo run --release -- vm --params-path params/kzg_bn254_12.srs --package-path ./example/ --circuit-name fibonacci prove -w example/witnesses/test_fibonacci-1747793629098.json
# Optional: verify locally.
cargo run --release -- vm --params-path params/kzg_bn254_12.srs --package-path ./example/ --circuit-name fibonacci verify -k 9 --pubs-path example/proofs/test_fibonacci-1747793629098.instance --proof-path example/proofs/test_fibonacci-1747793629098.proof
```

## Verify proof on-chain

See TUTORIAL.md<https://github.com/zkmove/halo2-verifier.move/blob/main/TUTORIAL.md>.