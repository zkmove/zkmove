## CLI for zkMove Virtual Machine

Currently, we only support one command 'Run', which run the full sequence of circuit building, setup, proving, and verifying.
It also reports the proof size, prove time and verify time when the execution is successful.

For example, the following command will first compile add.move into bytecode,
then build the circuit and setup the proving/verifying key, and then generate a zkp for the execution with the proving key and
finally verify the proof with the verifying key.

```bash
zkmove run -s examples/scripts/add.move
```

### Import modules
The Move program consists of scripts and modules. For testing, directive 'mods' can be added to script source file to import a module. For example,

```rust
/// call_u8.move

//! mods: arith.move
//! args: 1u8, 2u8
script {
    use 0x1::M;
    fun main(x: u8, y: u8) {
        M::add_u8(x, y);
    }
}
```
And we need tell vm where to load the module with option '-m':

```bash
zkmove run -s examples/scripts/call_u8.move -m examples/modules/
```
### Pass arguments
As you may have noticed, directive 'args' is used to pass arguments to scripts. There is also a command
option '--new-args' can be used to pass arguments, but these two methods have different purpose.

When using '--new-args', vm first runs the script with the old arguments (set by the directive 'args') and generates the
proving/verifying keys. Then, the script is run with the new arguments and the zkp is generated/verified with the **old** proving/verifying
keys. For example,

```rust
/// call_u8.move

//! mods: arith.move
//! args: 1u8, 2u8
script {
    use 0x1::M;
    fun main(x: u8, y: u8) {
        M::add_u8(x, y);
    }
}
```

```bash
zkmove run -s examples/scripts/call_u8.move -m examples/modules/ --new-args 3u8 4u8
```

### Generics
Zkmove also supports generics. just passing `ty_args` along with arguments. For example: ./examples/scripts/generic_type.move

run it with zkmove:

``` bash
zkmove run -s examples/scripts/generic_type.move -m examples/modules/
```

and run it with new args:

```bash
zkmove run -s examples/scripts/generic_type.move -m examples/modules/ --new-args 0x1 3u8 4u8
```

### Handle loops and conditional branch
If there is a conditional branch or loop in the code, the execution path will not be a fixed one.
When setup proving/verifying keys for such vm circuit, user can configure the number of execution steps and read/write
operations (include stack ops and locals ops). Empty steps or operations will be filled if the number of the actual
execution steps or operations is less than the configured number. For example,

```rust
/// fibonacci.move

//! circuit: vm
//! step_max_row: 1000
//! stack_ops_num: 1000
//! locals_ops_num: 1000
//! args: 11u8
script {
    fun main(n: u8) {
        let value1 = 0u128;
        let value2 = 1u128;
        let fibo = 0u128;

        let i = 0u8;
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
```bash
zkmove run -s examples/scripts/fibonacci.move
```

### Word capacity


To efficiently represent a complex value in the circuit, Version 0.2.0 introduces the concept of 'word', a uniform flattened value representation, to flatten the complex value into simple values. and developers can configure the circuit param `word_capacity` to specify the max number of simple values that a complex value can include.

for example, in `examples/scripts/vector3.move`, we set the param to 26, and you can run it with `zkmove run -s examples/scripts/vectors.move`.