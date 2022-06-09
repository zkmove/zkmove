<p align="center">
    <img alt="Website" src="https://img.shields.io/website?down_message=offline&label=zkmove.net&up_message=online&url=https%3A%2F%2Fzkmove.net">
    <a href="https://discord.gg/d6yMS2yycq"><img src="https://img.shields.io/discord/907903191788683304?logo=discord"/></a>
    <a href="https://twitter.com/zkmove"><img src="https://img.shields.io/twitter/follow/zkmove?style=social"/></a>
</p>

## zkMove

zkMove is a zero-knowledge proof friendly Move language runtime environment. It is both a scaling and privacy solution rolled into one..

### Highlights

**Powered by Move language and PLONK**. As a new generation of programming language for digital assets, Move guarantees secutiry of assets at the language level. Halo2 provides excellent tools for writing plonkish ciruit.

**Build a zero-knowledge proof-friendly bytecode virtual machine**. It greatly improves the programmability of zero-knowledge applications.

**Turing-completeness and fast mode**. Two types of circuits are combined: VM circuits to handle conditional branches and loops, and Move circuits, which enable bytecodes to be compiled directly into PLONKish, with smaller proof size and shorter proving time. 

### Example

We have prepared a [demo](./demo/README.md) with some examples to demonstrate the functionality of the zkMove virtual machine. 

For example, the following command will first compile add.move into bytecode, execute the bytecode to generate an execution trace, then build the circuit and setup the proving/verifying key, and then generate a zkp for the execution with the proving key and finally verify the proof with the verifying key.

```bash
bin/zkmove run -s examples/scripts/add.move
```

### Performance


### Limitations and issues

The project is still in an early stage. There are many limitations and issues in the virtual machine. For example, there is a lack of support for global state and only simple data types are supported. Moreover, the performance of both the circuit and the underlying proof system needs further improvement.
## License

zkMove is licensed as [Apache 2.0](./LICENSE).

