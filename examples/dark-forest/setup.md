# Setup Instructions

## For developer

Assume the zkmove verifier has already been set up on aptos, and the kzg setup params is ready on-chain. What you need to do is to publish your circuit to aptos.

```shell
cargo run --release --  --param-path ../../cli/params/kzg_bn254_12.srs aptos --zkmove-address @verifier_api -p ./ build-publish-circuit-aptos-txn
```
It will output a json file which you can take as input to `aptos move run --json-file`.

## For users

If the user want to create mother planet at coordinate `[123,45]`, he needs hide the coordinate with a off-chain hash function `coord_hash()`.

### 1.generate trace
```shell
move build --skip-fetch-latest-git-deps
move sandbox publish --skip-fetch-latest-git-deps --ignore-breaking-changes
move sandbox run --skip-fetch-latest-git-deps --witness storage/0x0000000000000000000000000000000000000000000000000000000000000002/modules/off_chain.mv coord_hash --args 123u128 45u128 5396936627018144388256392133700981730161373533767880136248396757995540825894u256
```
Trace file will be generated under ./witnesses by default. Assume it's `witnesses/coord_hash-1763607969148.json`.

### 2.generate proof

```shell
cargo run --release --  --param-path ../../cli/params/kzg_bn254_12.srs vm prove --package-path ./ -w witnesses/coord_hash-1763607969148.json --pubs-indices 2
```
Proof and public input files will be generated under ./proofs by default. Assume they're `proofs/coord_hash-1763607969148.proof` and `proofs/coord_hash-1763607969148.instance`.

### 3.verify proof on chain

Then the user can invoke the entry function `create_planet()` with the proof and the coord_hash as inputs.
 
