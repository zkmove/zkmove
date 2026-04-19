# Circuit Design

## Core Requirements of Any zkVM Circuit

Regardless of architecture, every zkVM circuit must ensure three fundamental correctness properties:

1. **Correct instruction loading** — the right instructions are fetched for execution.
2. **Correct instruction execution** — each instruction is executed according to its defined semantics.
3. **Memory consistency** — every value read from memory equals the value most recently written to that location.

The following sections compare how mainstream zkVMs address these requirements and outline zkMove's design choices.

## 1. Correct Instruction Loading

### RISC Zero Approach
The full RISC-V ELF binary is loaded into initial memory. A Merkle tree is constructed over the memory pages using the Poseidon2 hash function, with the circuit enforcing the Merkle tree's correctness. Proving overhead scales with the complexity of the Poseidon2 and Merkle tree circuits.

### Succinct SP1 Approach
Program instructions are loaded directly as the initial memory state of the MemoryLocalChip. This state is exposed as a public trace/table, allowing the circuit to reference instructions with almost zero additional proving overhead. Compared to RISC Zero’s Merkle-tree-based approach, this design significantly reduces circuit complexity and proving cost, but at the expense of program privacy — the bytecode becomes publicly visible.

### zkMove Approach
zkMove stores the contract bytecode in a fixed lookup table (a constant/fixed column in the Halo2 circuit). Thanks to the compact nature of Move bytecode, this table has negligible impact on proof size, with instruction fetching overhead approximately O(1).The fixed table is baked into the circuit, and its commitment is included in the Verification Key (VK) for that specific contract, keeping the program bytecode private.

## 2. Correct Instruction Execution

### Selector-Based Dispatch in Mainstream zkVMs

Mainstream zkVMs employ *selector columns* to dispatch instruction semantics. For a RISC-V ISA with $n$ instructions, each instruction $i$ defines a set of semantic constraint polynomials:

$$c_i(\mathbf{x}) = 0$$

where $\mathbf{x}$ denotes the relevant execution trace columns (e.g., `clk`, `pc`, `opcode`).

Each selector column $s_i$ satisfies:

$$s_i \cdot (s_i - 1) = 0 \quad \text{(each selector is a boolean)}$$

$$\sum_{i=0}^{n} s_i = 1 \quad \text{(exactly one instruction is active per row)}$$

The combined constraint polynomial across the execution trace is:

$$\sum_{i=0}^{n} s_i(\mathbf{x}) \cdot c_i(\mathbf{x}) = 0$$

This approach evaluates *all* $n$ instruction constraints per row, even though only one is active.

### zkMove Approach: Function-Scoped Circuits

zkMove scopes its circuit to only the opcodes used in the current function. Let $m$ denote the number of distinct opcodes in that function. The main constraint polynomial simplifies to:

$$\sum_{i=0}^{m} s_i(\mathbf{x}) \cdot c_i(\mathbf{x}) = 0$$

This design offers two key properties:

- **Best case** ($m = 1$): A trivial function with only a `ret` instruction reduces to $c_0(\mathbf{x}) = 0$, incurring zero dispatch overhead. (Note: This is an idealized case; in practice, even the simplest functions require a small set of basic instructions for function prologue and return handling.)
- **Worst case** ($m = n$): A function using all opcodes, the constraint falls back to the standard mainstream form — incurring no additional cost.

In practice, in most privacy-sensitive scenarios, most functions use only a small subset of opcodes, making zkMove’s circuit significantly more compact than general-purpose zkVM circuits.

## 3. Memory Consistency Checking

Early zkVMs relied on *sorting-based* methods[1] for memory consistency verification. Modern zkVMs, including zkMove, have adopted the **shuffle argument** instead.

zkMove integrates execution and memory into a single unified chip to minimize circuit size. By applying the *address-cycle* method[2], memory consistency is verified through **a single shuffle operation**, reducing inter-chip communication and circuit complexity.

## The Unique Challenges of Move

Unlike other smart contract languages, Move is uniquely equipped with **runtime type safety**. In the MoveVM, all values on the stack and in local variables are typed, contrasting sharply with languages like EVM, where types collapse to `U256` at runtime.

This poses two circuit design challenges:

- How to represent typed values within the circuit.
- How to enforce type checks without substantial performance overhead.

### zkMove's Solution

Complex types are *flattened* into a list of primitive type, represented as a tuple:

```
(index, sub_index, value, value_header)
```

Type checks are enforced only in three scenarios:
- When passing arguments to a function.
- When creating a new value.
- When modifying an existing value.

In all other cases, the Memory Consistency Check (MCC) ensures a value's type remains consistent across reads and writes. This approach maintains Move's type safety guarantees without appreciably increasing circuit size.

---

This document provides a high-level overview of zkMove's circuit design. For detailed technical specifications, refer to the zkMove Circuit Design Document.

[1]: David Wong. *Cairo's Public Memory.* [https://www.cryptologie.net/article/603/cairos-public-memory](https://www.cryptologie.net/article/603/cairos-public-memory)

[2]: Yibin Yang and David Heath. *Two Shuffles Make a RAM: Improved Constant Overhead Zero-Knowledge RAM* (2023). [https://eprint.iacr.org/2023/1115](https://eprint.iacr.org/2023/1115)
