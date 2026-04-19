# Background

## The Evolution of Smart Contract Platforms

Smart contract platforms have gone through three major evolutionary stages:

| Period | Representative | Key Characteristics |
|-|----------------|---------------------|
| 2015–2018 | Ethereum | First Turing-complete smart contract platform |
| 2018–2022 | Solana | Parallel execution, high throughput (TPS) |
| 2022–2026 | Sui / Aptos | Extreme parallelism, high TPS, asset-oriented design, enhanced security |

In parallel, Ethereum pioneered a different scaling path through Layer 2 (L2) rollups. Although L2 networks still have relatively limited decentralization, they have largely relieved Ethereum's scalability pressure.

## Privacy as the Next Priority

As the Agentic Economy continues to evolve, AI agents will operate with increasing autonomy — independently managing wallets, calling APIs, executing transactions, and collaborating with one another at scale. Without robust privacy protections, these agents risk exposing users’ behavioral patterns, intents, and asset information, thereby creating new attack surfaces and pervasive surveillance vectors.

To become a truly trustworthy coordination layer for the Agentic Economy, existing smart contract platforms must close this critical privacy gap. Zero-knowledge proofs (ZKPs) stand out as one of the most powerful technologies capable of addressing this challenge.

## Zero-Knowledge Proofs and zkVMs

**Zero-knowledge proofs (ZKPs)** are a cryptographic primitive that allow a prover to convince a verifier that a computation was performed correctly, without revealing any information about the underlying inputs.

ZKPs have broad applications in:

- Blockchain scaling — enabling efficient off-chain computation with succinct on-chain verification (e.g., zk-Rollups).
- Privacy protection — proving the validity of transactions or credentials while fully concealing sensitive data, intents, and assets.
- Verifiable computation — moving complex processing off-chain while maintaining cryptographic trust.
- Blockchain interoperability — supporting trustless cross-chain verification and data bridging.

Despite their potential, ZKPs have historically suffered from poor programmability. Building a ZKP application typically requires cryptography experts to hand-craft arithmetic circuits — a time-consuming process that has hindered mainstream adoption.

A **zero-knowledge virtual machine (zkVM)** targeting general-purpose programming languages addresses this problem. With a zkVM, developers write ordinary code and the system automatically generates efficient proofs, dramatically lowering the barrier to building ZKP applications.

## What is zkMove?

**zkMove** is a secure, high-performance zero-knowledge virtual machine (zkVM) designed specifically for the Move programming language. It empowers Move smart contracts to access and process private data in a fully programmable and trustless manner.
