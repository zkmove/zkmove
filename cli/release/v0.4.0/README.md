## CLI for zkMove Virtual Machine

Let‘s start with an example. Before you begin, extract the zkmove binary file to the directory 'example'. And make sure you have a customized version of the Move CLI installed.

```shell
cargo install --git https://github.com/zkmove/aptos-core move-cli --branch witnessing
```

First, build and publish the example.
```shell
cd example
move build
move sandbox publish --skip-fetch-latest-git-deps --ignore-breaking-changes
```

Then generate the witness while executing the example. By default, the witness will be generated in a directory called `witnesses`.
```shell
move sandbox run --skip-fetch-latest-git-deps --witness storage/0x0000000000000000000000000000000000000000000000000000000000000001/modules/fibonacci.mv test_fibonacci --args 10u64
```
Finally, execute the “zkmove run” command, which will run the full sequence of setup, proving and verification. Upon successful execution, it will also report the proof size, proving time, and verification time.

```shell
# Don't forget to replace the witness filename with your own.
./zkmove run -w witnesses/test_fibonacci-1733485309514.json
```