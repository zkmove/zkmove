<p align="center">
    <img alt="Website" src="https://img.shields.io/website?down_message=offline&label=zkmove.net&up_message=online&url=https%3A%2F%2Fzkmove.net">
    <a href="https://discord.gg/d6yMS2yycq"><img src="https://img.shields.io/discord/907903191788683304?logo=discord"/></a>
    <a href="https://twitter.com/zkmove"><img src="https://img.shields.io/twitter/follow/zkmove?style=social"/></a>
</p>

## zkMove

zkMove is a zero-knowledge proof friendly Move language runtime environment. We can build scaling and privacy solution based on it.

### Overview

**A zero-knowledge proof-friendly bytecode virtual machine**, to improve programmability and composability of zk-proof application.

**Powered by Move language and Halo2**. As a new generation of programming language for digital assets, Move guarantees security of assets at the language level. Halo2 uses Plonkish arithmetization, fitable for constructing complicated circuits. No trusted setup required

**No compromise on performance while pursuing Turing completeness**. Two types of circuits are combined: VM circuits to handle conditional branches and loops, and Move circuits, which directly compiled from bytecodes, offer smaller proof size and shorter proving time. 

### Example

We have prepared a [demo](./demo/README.md) with some examples to demonstrate the functionality of the zkMove virtual machine. 

For example, the following command will first compile add.move into bytecode, execute the bytecode to generate an execution trace, then build the circuit and setup the proving/verifying key, and then generate a zkp for the execution with the proving key and finally verify the proof with the verifying key.

```bash
bin/zkmove run -s examples/scripts/add.move
```

### Source code

**Move circuit:** https://github.com/young-rocks/zkmove-lite

**VM circuit:** we plan to make the source code available later this year


## License

zkMove is licensed as [Apache 2.0](./LICENSE).

