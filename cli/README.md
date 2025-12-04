## CLI for zkMove Virtual Machine

Before start, make sure you have a customized version of the Move CLI installed:

```shell
cargo install --git https://github.com/zkmove/aptos-core move-cli --branch witnessing
```

Build and publish the example. Then generate the witness while executing the example. By default, the witness will be
generated in a directory called `witnesses`.

```shell
# Run below commands cli/example/
move build
move sandbox publish --skip-fetch-latest-git-deps --ignore-breaking-changes
move sandbox run --skip-fetch-latest-git-deps --witness storage/0x0000000000000000000000000000000000000000000000000000000000000001/modules/fibonacci.mv test_fibonacci --args 10u64
```

```shell
# Generate proof in the client-side. Run under cli/, don't forget to replace the witness filename with your own.
cargo run --release --  --param-path params/kzg_bn254_12.srs vm prove --package-path example -w example/witnesses/test_fibonacci-1747793629098.json
# As a debug tool, user can verify the proof in the client-side.
cargo run --release --  --param-path params/kzg_bn254_12.srs vm verify -k 9 --package-path example --pubs-path example/proofs/test_fibonacci-1747793629098.instance --proof-path example/proofs/test_fibonacci-1747793629098.proof
```

To publish the circuit to Aptos, you can use the following command to create the transaction(make sure the on-chain verifier is deployed already, and replace the zkmove-address with your own):
```shell
cargo run --release --  --param-path params/kzg_bn254_12.srs aptos --zkmove-address a9f85ec000d6b7e78aa006f0fe0fcb3f8b82b71262283b84f2434441318064e1 -p ./example build-publish-circuit-aptos-txn -w example/witnesses/test_fibonacci-1747793629098.json
```
Verify the proof on Aptos, use the following command to create the transaction:
```shell
# todo: remove unused param-path, package_dir
cargo run --release --  --param-path params/kzg_bn254_12.srs aptos --zkmove-address a9f85ec000d6b7e78aa006f0fe0fcb3f8b82b71262283b84f2434441318064e1 -p ./example build-verify-proof-aptos-txn --pubs-path example/proofs/test_fibonacci-1754384516414.instance --proof-path example/proofs/test_fibonacci-1754384516414.proof --param-address a9f85ec000d6b7e78aa006f0fe0fcb3f8b82b71262283b84f2434441318064e1 --circuit-address a9f85ec000d6b7e78aa006f0fe0fcb3f8b82b71262283b84f2434441318064e1 --kzg shplonk
```