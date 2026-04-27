# zkMove: Programmable Privacy for Move Smart Contracts

<div style="text-align: center;">

<span style="font-size: 1.1em;">zkMove Team</span>

<span style="display: block;">contact@zkmove.net</span>

<span style="display: block; margin-top: 1em;">April 2026</span>

</div>

## Abstract

As performance bottlenecks in smart contract platforms continue to ease, privacy has emerged as the next critical challenge. The transparent nature of blockchains inherently exposes users’ behavioral patterns, intentions, and asset holdings.

This concern becomes even more acute as blockchains and smart contracts are positioned as the trustworthy coordination layer for the Agentic Economy. Hidden vulnerabilities in applications become easier for attackers to discover and exploit, while AI agents themselves introduce entirely new attack surfaces.

**zkMove** is a secure, high-performance zero-knowledge virtual machine (zkVM) purpose-built for the Move programming language. It empowers Move smart contracts to access and process private data in a fully programmable and trustless manner.

From a product perspective, zkMove serves as both middleware and an SDK, enabling Move developers to build privacy-preserving decentralized applications without deep cryptographic expertise.

This litepaper presents:

- The motivation for introducing programmable privacy to the Move ecosystem
- How to build a privacy-focused zkVM for Move
- zkMove’s ASIC-inspired circuit architecture and its hybrid on-chain/off-chain computation model
- Core circuit design, including instruction loading, function-scoped execution, memory consistency, and support for Move’s unique runtime type system
- Performance benchmarks of zkMove v0.5, highlighting improvements in proving time and proof size
- Representative use cases such as confidential assets and incomplete-information games

## Acknowledgements

We are grateful to *Shisheng Li*, *Ryan Fang*, *Star Li*, *Tim Yang*, and *Xiaofeng Li* for their valuable advice and support throughout the development of this project.
