# zkMove Documentation

Welcome to the official documentation for **zkMove** — a zero-knowledge virtual machine (zkVM) for the [Move](https://move-language.github.io/move/) language. zkMove enables developers to generate succinct zero-knowledge proofs for Move programs, unlocking programmable privacy and verifiable computation on-chain.

---

## Table of Contents

### Introduction

Understand the motivation, design principles, and internals of zkMove.

| # | Page | Description                                              |
|---|------|----------------------------------------------------------|
| 1 | [Background](introduction/background.md) | Zero-knowledge proofs, zkVMs, and why they matter        |
| 2 | [zkVM for Move](introduction/zkvm-for-move.md) | Why Move and how to develop a zkVM for the Move language |
| 3 | [Architecture](introduction/architecture.md) | High-level architecture of zkMove                        |
| 4 | [Circuit Design](introduction/circuit-design.md) | Design of the zkMove circuit                             |
| 5 | [Performance](introduction/performance.md) | Performance analysis and benchmarks                      |
| 6 | [Use Cases](introduction/use-cases.md) | Real-world applications enabled by zkMove                |

### User Guide

Set up your environment, write Move programs, generate proofs, and verify them on-chain.

| # | Page | Description                                      |
|---|------|--------------------------------------------------|
| 1 | [Set Up the Dev Environment](user/setup-dev-environment.md) | Configure your development environment           |
| 2 | [Circuit and Proof](user/circuit-and-proof.md) | Compile a Move program and generate the ZK proof |
| 3 | [Deploy an On-Chain Verifier](user/deploy-on-chain-verifier.md) | Deploy the on-chain verifier on a local devnet   |
| 4 | [Verify a Proof On-Chain](user/verify-proof-on-chain.md) | Submit and verify a proof on the local devnet    |
