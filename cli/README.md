## CLI for zkMove Virtual Machine

Let us introduce the usage of CLI through an example. Before you begin, make sure you have a customized version of the
Move CLI installed.

```shell
cargo install --git https://github.com/zkmove/aptos-core move-cli --branch witnessing
```

First, build CLI for zkMove.

```shell
cargo build --bin zkmove --release --artifact-dir ./cli/example/ -Z unstable-options
cd cli/example
```

Build and publish the example. Then generate the witness while executing the example. By default, the witness will be
generated in a directory called `witnesses`.

```shell
move build
move sandbox publish --skip-fetch-latest-git-deps --ignore-breaking-changes
move sandbox run --skip-fetch-latest-git-deps --witness storage/0x0000000000000000000000000000000000000000000000000000000000000001/modules/fibonacci.mv test_fibonacci --args 10u64
```

Finally, execute the “zkmove run” command, which will run the full sequence of setup, proving and verification. Upon
successful execution, it will also report the proof size, proving time, and verification time.

```shell
# Don't forget to replace the witness filename with your own.
zkmove run -p example -w witnesses/test_fibonacci-1733485309514.json
```

### setup kzg param to aptos

``` shell
❯ aptos move run --function-id a9f85ec000d6b7e78aa006f0fe0fcb3f8b82b71262283b84f2434441318064e1::param_store::create --args hex:0x0100000000000000000000000000000000000000000000000000000000000000 hex:0xedf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19 hex:e4115200acc86e7670c83ded726335def098657fe8668323e9e41e6781b83b0a9d83b54bbb00215323ce6d7f9d7f331a286d7707d03f7dbdd3125c6163588d13
Do you want to submit a transaction for a range of [53600 - 80400] Octas at a gas unit price of 100 Octas? [yes/no] >
yes
{
  "Result": {
    "transaction_hash": "0xb3e2a1c321b2248ccf4d7cc51c0ae939f6d47b4794b49ab5cbe8692800c39938",
    "gas_used": 536,
    "gas_unit_price": 100,
    "sender": "1d8ef3c583e8407daca3e0231970ad2011748b9909432209565d29a60f4fa5f0",
    "sequence_number": 0,
    "success": true,
    "timestamp_us": 1733970335336627,
    "version": 3809837,
    "vm_status": "Executed successfully"
  }
}
```

### build publish-circuit aptos txn

```shell
cargo run -- --param-path challenge_0078-kzg_bn254_16.srs -k 12 aptos --verifier-address a9f85ec000d6b7e78aa006f0fe0fcb3f8b82b71262283b84f2434441318064e1 --package_dir example/ build-publish-vk-aptos-txn --entry_module 0x1::fibonacci --function_name test_fibonacci --max_rows 2048
```

### build verify-proof aptos txn
