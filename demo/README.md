## CLI for zkMove Virtual Machine

Currently, we only support one command 'Run', which run the full sequence of circuit building, setup, proving, and verifying. 
It also reports the proof size, prove time and verify time when the execution is successful.

For example, the following command will first compile add.move into bytecode,
then build the circuit and setup the proving/verifying key, and then generate a zkp for the execution with the proving key and 
finally verify the proof with the verifying key.

```bash
bin/zkmove run -s examples/scripts/add.move
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
bin/zkmove run -s examples/scripts/call_u8.move -m examples/modules/
```
### Pass arguments
As you may have noticed, directive 'args' is used to pass arguments to scripts. There is also a command 
option '--new-args' can be used to pass arguments, but these two methods have different purpose. 

When using '--new-args', vm first runs the script with the old arguments (set by the directive 'args') and generates the 
proving/verifying keys. Then, the script is run with the new arguments and the zkp is generated/verified with the **old** proving/verifying 
keys. For example,

```rust
/// add_u8.move

//! args: 1u8
script {
    fun main(x: u8) {
        x + 2u8;
    }
}
```

```bash
bin/zkmove run -s examples/scripts/add_u8.move --new-args 2u8
```

### Enable fast circuit
zkMove supports two types of circuits: the move circuit and the vm circuit. By default the move circuit is used. 
Move circuit is ~40 times faster than vm circuit, but it's not Turing-complete. The vm circuit is Turing complete but slow. 
We can enable the vm circuit via the command option "--vm-circuit" or use directive 'circuit: vm'.

```bash
bin/zkmove run -s examples/scripts/add.move --vm-circuit
```

### Handle loops and conditional branch
If there is a conditional branch or loop in the code, the execution path will not be a fixed one. 
When setup proving/verifying keys for such vm circuit, user can configure the number of execution steps and read/write 
operations (include stack ops and locals ops). Empty steps or operations will be filled if the number of the actual 
execution steps or operations is less than the configured number. For example,

```rust
/// fibonacci.move

//! circuit: vm
//! steps_num: 1000
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
bin/zkmove run -s examples/scripts/fibonacci.move
```

### Enable fast circuit
zkMove supports two types of circuits: the vm circuit and the move circuit. By default the vm circuit is used, 
which is Turing complete but slow. Move circuit is 100 times faster than vm circuit, but it's not Turing-complete. 
We can enable the move circuit via the command option "--fast-mode".

```bash
bin/zkmove run -s examples/scripts/add.move -f
```
