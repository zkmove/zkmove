# Architecture

## Mainstream ZKVM: A Two-Layer Architecture

General-purpose ZKVMs — such as RISC Zero and Succinct SP1, both based on the RISC-V instruction set — are primarily designed for broad computational use cases, including blockchain scaling and off-chain co-processors. They typically adopt a **two-layer circuit architecture** to balance proving efficiency with on-chain verification cost.

**Layer 1: RISC-V Execution Circuit → STARK Proof**

- Proves correct program execution on the RISC-V virtual machine using the zk-STARK protocol.
- *Strengths:* Transparent setup (no trusted setup required), post-quantum secure, relatively efficient proof generation.
- *Weakness:* Produces large proof sizes (typically hundreds of kilobytes).

**Layer 2: Compression / Recursion Circuit → Groth16 SNARK**

- Aggregates and compresses the Layer 1 STARK proof into a Groth16 SNARK (over the BN254 curve).
- Produces a **constant-size proof** suitable for on-chain verification with low gas cost.

## zkMove: An ASIC-Inspired Architecture

### Single-Layer Design

zkMove draws inspiration from **ASIC (Application-Specific Integrated Circuit)** design philosophy. Rather than targeting universal computation, zkMove generates a **dedicated circuit and verification key** for each application, tailored to the specific set of opcodes that application uses.

Compared to the two-layer architecture of mainstream ZKVMs, this approach yields several key benefits:

- **Minimal proof size** — typically only tens of kilobytes.
- **No compression layer required** — proofs can be verified on-chain directly, without recursive aggregation.
- **Near-instant finality** — on-chain verification can be completed in approximately 1 second.

### On-Chain / Off-Chain Hybrid Computation

For complex computations, zkMove’s dedicated circuit can grow nearly as large as a general-purpose ZKVM circuit, diminishing the benefits of its ASIC-like design.

To address this, zkMove introduces an **on-chain / off-chain hybrid computation model**. Developers can separate privacy-sensitive state and logic from the main smart contract and define them as one or more *off-chain functions*. These functions execute on the client side and generate zero-knowledge proofs. The on-chain contract then performs only lightweight verification of the submitted proofs, while executing the remaining logic fully on-chain.

This hybrid approach delivers the best of both worlds:

- **On-chain transparency and security** — core contract logic remains fully public and verifiable on-chain, eliminating the need to generate zero-knowledge proofs for it.
- **Off-chain privacy** — sensitive data and computations never leave the user’s client.

## Strengths and Trade-offs

### Strengths of zkMove

- **Client-side proving** — User inputs and sensitive data remain private on the client and are never exposed to third parties.
- **Fast finality** — Proofs require no recursive compression and can be verified directly on-chain, enabling near one-second finality.
- **Full decentralization and trustlessness** — zkMove inherits the same security guarantees as the underlying L1 blockchain.
- **On-chain / off-chain hybrid computation** — Supports seamless mixing of on-chain and off-chain logic without deploying a separate L2, thereby avoiding fragmentation of the L1 ecosystem.
- **Seamless tooling compatibility** — Fully compatible with existing Move development tools; current Move programs can run without any code modifications.

### Trade-offs

- Each application requires its own dedicated **verification key**, which increases deployment and key management overhead compared to general-purpose ZKVMs.

> **Summary:** Mainstream ZKVMs excel at general-purpose computation and are well-suited for L2 scaling. zkMove is purpose-built for privacy-preserving computation, making it an ideal choice for programmable privacy on Layer 1.
