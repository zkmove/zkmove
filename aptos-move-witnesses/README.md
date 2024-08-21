### aptos move witnesses generation

We make some changes to the standard move cli in aptos to support witness generation of move code.
So you can just use the following commands to get the witnesses in json.

Install `move` command from https://github.com/zkmove/aptos-core/tree/witnessing

```shell
cargo install --git https://github.com/zkmove/aptos-core move-cli --branch witnessing
```

Then run the example:

```
cd examples/witness-generation
move build
move sandbox run --witness storage/0x0000000000000000000000000000000000000000000000000000000000000001/modules/vectoring.mv test_vec_swap
```