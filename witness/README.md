### move witnesses generation

We make some changes to the standard move cli to support witness generation of move code.
So you can just use the following commands to get the witnesses in json.

Install `move` command from https://github.com/zkmove/move/tree/main

```shell
cargo install --git https://github.com/zkmove/move move-cli --branch main
```

Then run the example:

```
cd example/witness-generation
move build
move sandbox publish
move sandbox run --witness storage/0x0000000000000000000000000000000000000000000000000000000000000001/modules/vectoring.mv test_vec_swap
```