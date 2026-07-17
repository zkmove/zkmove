#  Tutorial on zkMove CLI

This guide explains how to use `zkmove` CLI to create a circuit and generate a proof for it.

> The `zkmove` CLI now generates witnesses itself (`zkmove vm ... run`), so a separate
> Move CLI is no longer required for the basic flow. You still need the Move compiler
> (`move build`) to compile your package once.

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

First, compile the example package:

```shell
# Run under the package root.
move build --skip-fetch-latest-git-deps
```

Then generate the witness by executing the entry function. The entry (module + function)
is read from the `[circuit.<name>].entry` section of `Move.toml`. By default, witnesses are
written to `<package-path>/witnesses/`.

```shell
cargo run --release -- vm --package-path ./example/ --circuit-name fibonacci run --args 10u64
```

`run` accepts `--args` (e.g. `10u64 true 0x1`) and `-o/--output-dir`.
The compiled modules of the package are loaded into in-memory storage automatically; no separate
`move sandbox publish` is needed.

## Generate circuit artifacts

Circuit artifacts can be generated from the circuit metadata in `Move.toml`:

```shell
cargo run --release -- vm --package-path ./example/ --circuit-name fibonacci setup --params-path params/kzg_bn254_12.srs
```

If the circuit size is not known yet, generate a witness first and use it to size setup:

```shell
cargo run --release -- vm --package-path ./example/ --circuit-name fibonacci setup --params-path params/kzg_bn254_12.srs -w example/witnesses/test_fibonacci-1747793629098.json
```

The setup command writes `params.bin`, `pk.bin`, `vk.bin`, and `metadata.json` to
`<package-path>/setup` by default. The `metadata.json` file records the setup `k`
and public input indices used by later commands.

## Generate the proof

Note: `prove` and `verify` load circuit artifacts from `<package-path>/setup` by default.
Use `--setup-dir` to point them at a different setup output directory.

```shell
# Running in the package root. `prove` can generate the witness internally.
cargo run --release -- vm --package-path ./example/ --circuit-name fibonacci prove --args 10u64

# Or prove from an existing witness file.
cargo run --release -- vm --package-path ./example/ --circuit-name fibonacci prove -w example/witnesses/test_fibonacci-1747793629098.json

# Optional: verify locally.
cargo run --release -- vm --package-path ./example/ --circuit-name fibonacci verify --pubs-path example/proofs/test_fibonacci-1747793629098.instance --proof-path example/proofs/test_fibonacci-1747793629098.proof
```

## Verify proof on-chain

See TUTORIAL.md<https://github.com/zkmove/halo2-verifier.move/blob/main/TUTORIAL.md>.
