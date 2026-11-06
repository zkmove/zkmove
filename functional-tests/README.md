## Tests

The crate contains one Move module (and one circuit) per functional test case.
Every case is declared as a `[circuit.<case>]` entry in `Move.toml`; the entry
carries the circuit's `max_execution_rows`/`max_poseidon_rows`, its entry
function and (if needed) its arguments.

First, generate the witnesses and the manifest:

```bash
bash gen_witness.sh
```

This runs `zkmove vm run-all`, which compiles the package, executes every
`[circuit.*]` entry and writes `witnesses/<case>.json` plus
`witnesses/manifest.json`.

Then run all cases with `cargo test --test testsuite`, or a single case with
`cargo test --test testsuite -- test_add`. The test suite reads the manifest so
each case is proved with its own circuit configuration.
