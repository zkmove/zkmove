# Introduction

## The Evolution of Smart Contract Platforms

The evolution of smart contract platforms has followed two distinct paths. The first is the Layer 2 (L2) scaling roadmap pioneered by Ethereum and its ecosystem. The second is the horizontal scaling approach taken by high-performance Layer 1 blockchains such as Solana, Sui, and Aptos. Both paths share the same core objective: dramatically improving performance and throughput.

The horizontal scaling approach has progressed through three major stages:

| Period    | Representative | Key Characteristics                              |
|-----------|----------------|--------------------------------------------------|
| 2015–2018 | Ethereum       | First Turing-complete smart contract platform    |
| 2018–2022 | Solana         | Parallel execution, high throughput (TPS)        |
| 2022–2026 | Sui / Aptos    | Extreme parallelism, high TPS, enhanced security |

To date, both approaches have largely delivered on their respective goals, notwithstanding the degree of decentralization sacrificed by L2 solutions.

## Privacy as the Next Priority

With performance largely addressed, privacy has emerged as the next critical challenge. The inherently public nature of blockchains exposes users' behavioral patterns, intents, and asset holdings — creating persistent surveillance and attack vectors for malicious actors.

This concern becomes even more acute as blockchains and smart contracts are increasingly positioned as the trustworthy coordination layer for the Agentic Economy. On one hand, hidden vulnerabilities in applications become easier for attackers to discover and exploit at scale. On the other hand, AI agents themselves introduce entirely new attack surfaces.

In Liu Cixin's *The Dark Forest*, the safest and most rational strategy in a universe that may harbor advanced civilizations is simple: do not reveal your position. Without robust privacy protections, blockchains risk becoming precisely such a "dark forest". Existing smart contract platforms must close this privacy gap to become a truly secure and trustworthy coordination layer for the Agentic Economy.

## Zero-Knowledge Proofs and zkVMs

**Zero-knowledge proofs (ZKPs, or simply ZK)** are a cryptographic primitive that allow a prover to convince a verifier that a computation was performed correctly, without revealing any information about the underlying inputs. As a rapidly evolving area of cryptography, ZK is seeing growing adoption across blockchain scaling, privacy protection, and verifiable computation.

Despite their potential, ZKPs have historically suffered from poor programmability. Building a ZKP application typically requires cryptography experts to hand-craft arithmetic circuits — a time-consuming process that has hindered mainstream adoption.

A **zero-knowledge virtual machine (zkVM)** addresses this problem directly. With a zkVM, developers write ordinary code and the system automatically generates efficient proofs, dramatically lowering the barrier to building ZKP-powered applications.

## Why Move?

The **Move programming language** was originally developed by Meta (Facebook) for writing smart contracts on the Libra blockchain, and has since been adopted by Sui and Aptos. Move's most distinctive feature is **asset-oriented programming**: digital assets are modeled as *resources* with strict ownership semantics — they cannot be copied, accidentally discarded, or double-spent, and must be explicitly transferred or destroyed.

Move is the natural choice for a privacy-focused zkVM for two reasons. First, The essence of blockchain is a value network, and its core purpose is to enable digital assets to move more efficiently. Second, Sui and Aptos represent the most important direction in the evolution of smart contract platforms — and building for Move means building where the ecosystem is headed.

## What is zkMove?

Technically, **zkMove** is a secure, high-performance zkVM designed specifically for the Move programming language. It empowers Move smart contracts to access and process private data in a fully programmable and trustless manner.

From a product perspective, zkMove is both a middleware and an SDK — one that Move developers can use to build privacy-preserving decentralized applications without deep cryptographic expertise.

zkMove's path to success hinges on two key challenges. First, the ZK space is evolving rapidly; staying competitive requires continuously advancing circuit design while keeping pace with improvements in the underlying proof systems. Second, whether Move's ecosystem can secure a meaningful role in the emerging Agentic Economy — and whether zkMove can deliver unique value within that ecosystem — are questions that deserve serious consideration.
