# Architecture

## Mainstream ZKVMs: A Two-Stage General-purpose Architecture

Mainstream ZKVMs such as RISC Zero and Succinct SP1, both based on the RISC-V instruction set, are primarily designed for general-purpose computation. They are widely used for blockchain scaling, off-chain co-processors, and other verifiable computing applications.These ZKVMs typically adopt a two-stage circuit architecture to balance proving efficiency with on-chain verification cost:

**Stage 1: RISC-V Execution Circuit → STARK Proof**

- Proves correct program execution on the RISC-V virtual machine using the zk-STARK protocol.
- *Strengths:* Transparent setup (no trusted setup required), post-quantum secure, relatively efficient proof generation.
- *Weakness:* Produces large proof sizes (typically hundreds of kilobytes to several megabytes).

**Stage 2: Compression / Recursion Circuit → Groth16 SNARK**

- Aggregates and compresses the Stage 1 STARK proof into a Groth16 SNARK (over the BN254 curve).
- Produces a **constant-size proof** suitable for on-chain verification with low gas cost.

## zkMove: An ASIC-Inspired Architecture

### Single-Stage

zkMove draws inspiration from **ASIC (Application-Specific Integrated Circuit)** design philosophy. Rather than targeting universal computation, zkMove generates a **dedicated circuit and verification key** for each application. The circuit is tailored to the specific set of opcodes that application uses.

Compared to the two-stage architecture of mainstream ZKVMs, this approach yields several key benefits:

- **Minimal proof size** — typically only tens of kilobytes (significantly smaller than the uncompressed STARK proofs from general-purpose zkVMs).
- **No compression stage required** — the final proof can be verified on-chain directly, eliminating the need for recursive aggregation or a secondary SNARK wrapper.

### On-Chain / Off-Chain Hybrid Computation

For complex computations, zkMove’s dedicated circuit can grow nearly as large as a general-purpose ZKVM circuit, diminishing the benefits of its ASIC-like design.

To address this, zkMove introduces an **on-chain / off-chain hybrid computation model**. Developers can separate privacy-sensitive state and logic from the main smart contract and define them as one or more *off-chain functions*. These functions execute on the user’s client and generate zero-knowledge proofs, with only the proofs being submitted on-chain. The on-chain contract then verifies the submitted proofs and executes the remaining logic.

This hybrid approach delivers the best of both worlds:

- **On-chain transparency and security** — core contract logic remains fully public and verifiable on-chain, eliminating the need to generate zero-knowledge proofs for it.
- **Off-chain privacy** — sensitive data and computations never leave the user’s client.

## Strengths and Trade-offs

### Strengths of zkMove

- **Client-side proving** — User inputs and sensitive data remain private on the client and are never exposed to third parties.
- **Instant finality** — Proofs are verified directly on-chain with instant finality.
- **Full decentralization and trustlessness** — zkMove inherits the same security guarantees as the underlying L1 blockchain.
- **Seamless tooling compatibility** — Fully compatible with existing Move development tools; current Move programs can run without any code modifications.

### Trade-offs

- Not suitable for highly complex off-chain computations
- Each application requires its own dedicated verification key, which increases deployment and key management overhead compared to general-purpose ZKVMs.

> **Summary:** Mainstream ZKVMs excel at general-purpose computation and are well-suited for L2 scaling. zkMove is purpose-built for privacy-preserving computation, making it an ideal choice for programmable privacy on L1.
