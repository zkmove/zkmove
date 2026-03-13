# Circuit and Proof

## Circuit Example

zkMove is designed to be developer-friendly and fits naturally into existing Move development workflows. By leveraging the standard Move package structure, zkMove lets you define zk circuits alongside your Move code with minimal configuration changes.

The example below is a Move module that computes the Fibonacci sequence. The full source is located at `cli/example`. We will build a zk circuit for the `test_fibonacci` entry function.

```move
// fibonacci.move
module 0x1::fibonacci {
    public entry fun test_fibonacci(n: u64) {
        let value1 = 0u256;
        let value2 = 1u256;
        let fibo = 0u256;

        let i = 0u64;
        while (i < n) {
            fibo = value1 + value2;
            value1 = value2;
            value2 = fibo;
            i = i + 1;
        };
        fibo;
    }
}
```

To define a circuit for this function, add a `[circuit.<name>]` section to the package manifest `Move.toml`. In this example, the circuit is named `fibonacci`:

```toml
[package]
name = "example"
version = "0.0.1"

[dependencies]
MoveStdlib = { git = "https://github.com/zkmove/aptos-core.git", subdir = "third_party/move/move-stdlib", rev = "witnessing" }

[addresses]
std = "0x1"

[circuit.fibonacci]
max_execution_rows = 278     # Max rows for the execution subcircuit.
max_poseidon_rows = 100      # Max rows for the Poseidon subcircuit.
entry = { module_id = "0x1::fibonacci", function_name = "test_fibonacci" }
```

---

## Generate a Witness

First, build and publish the example package:

```shell
# Run from the package root.
move build
move sandbox publish --skip-fetch-latest-git-deps --ignore-breaking-changes
```

Then execute the entry function to generate the witness. By default, witness files are written to the `witnesses/` directory:

```shell
move sandbox run --skip-fetch-latest-git-deps --witness \
  storage/0x0000000000000000000000000000000000000000000000000000000000000001/modules/fibonacci.mv \
  test_fibonacci --args 10u64
```

---

## Generate a Proof

Run the following command from the package root. Replace the witness filename with the one generated in the previous step:

```shell
zkmove vm \
  --params-path params/kzg_bn254_12.srs \
  --package-path ./ \
  --circuit-name fibonacci \
  prove -w witnesses/test_fibonacci-1747793629098.json
```

**Optional: verify locally before submitting on-chain.**

```shell
zkmove vm \
  --params-path params/kzg_bn254_12.srs \
  --package-path ./ \
  --circuit-name fibonacci \
  verify -k 9 \
  --pubs-path proofs/test_fibonacci-1747793629098.instance \
  --proof-path proofs/test_fibonacci-1747793629098.proof
```
