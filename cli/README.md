## CLI for zkMove Virtual Machine

Let us introduce the usage of CLI through an example. Before you begin, make sure you have a customized version of the Move CLI installed.

```shell
cargo install --git https://github.com/zkmove/aptos-core move-cli --branch witnessing
```

First, build CLI for zkMove.
```shell
cargo build --bin zkmove --release --artifact-dir ./cli/example/ -Z unstable-options
cd cli/example
```
Build and publish the example. Then generate the witness while executing the example. By default, the witness will be generated in a directory called `witnesses`.
```shell
move build
move sandbox publish --skip-fetch-latest-git-deps --ignore-breaking-changes
move sandbox run --skip-fetch-latest-git-deps --witness storage/0x0000000000000000000000000000000000000000000000000000000000000001/modules/fibonacci.mv test_fibonacci --args 10u64
```

Finally, execute the “zkmove run” command, which will run the full sequence of setup, proving and verification. Upon successful execution, it will also report the proof size, proving time, and verification time.

```shell
# Don't forget to replace the witness filename with your own.
./zkmove run -w witnesses/test_fibonacci-1733485309514.json
```