# zkMove Documentation

Welcome to the official documentation for **zkMove** — a zero-knowledge virtual machine (zkVM) for the [Move](https://move-language.github.io/move/) language. zkMove enables developers to generate succinct zero-knowledge proofs for Move programs, unlocking programmable privacy and verifiable computation on-chain.

---

## Table of Contents

### Litepaper

Understand the motivation, design principles, and internals of zkMove.

| # | Page                                          | Description                                         |
|---|-----------------------------------------------|-----------------------------------------------------|
| 1 | [Abstract](litepaper/abstract.md)             | Overview and scope of this litepaper                |
| 2 | [Introduction](litepaper/introduction.md)     | Background and motivation for building zkMove       |
| 3 | [zkVM for Move](litepaper/zkvm-for-move.md)   | How to develop a zkVM for the Move language         |
| 4 | [Architecture](litepaper/architecture.md)     | High-level architecture of zkMove                   |
| 5 | [Circuit Design](litepaper/circuit-design.md) | Design of the zkMove circuit                        |
| 6 | [Performance](litepaper/performance.md)       | Performance analysis and benchmarks                 |
| 7 | [Use Cases](litepaper/use-cases.md)           | Real-world applications enabled by zkMove           |
| 8 | [References](litepaper/references.md)         | All citations and references used in this litepaper |

### User Guide

Set up your environment, write Move programs, generate proofs, and verify them on-chain.

| # | Page | Description                                      |
|---|------|--------------------------------------------------|
| 1 | [Set Up the Dev Environment](user/setup-dev-environment.md) | Configure your development environment           |
| 2 | [Circuit and Proof](user/circuit-and-proof.md) | Compile a Move program and generate the ZK proof |
| 3 | [Deploy an On-Chain Verifier](user/deploy-on-chain-verifier.md) | Deploy the on-chain verifier on a local devnet   |
| 4 | [Verify a Proof On-Chain](user/verify-proof-on-chain.md) | Submit and verify a proof on the local devnet    |
