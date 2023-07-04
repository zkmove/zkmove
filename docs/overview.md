## zkMove: a zero-knowledge proof-based smart contract runtime environment


#### 1.Background

Mass adoption of Web3 is not happening as quickly as we thought. There are some issues to be resolved.

Scalability is one barrier to the adoption of smart contracts. With the emergence of various layer2 and high tps public chains, this problem is being worked on.

Another issue is privacy. The public and transparent nature of blockchain is great for many use cases, but makes it very hard to adopt for other use cases like payment, social, etc.

Security is another issue often criticized. Security vulnerabilities are often found in smart contracts. Layer2 will definitely be the hardest hit.

A large number of innovations based on zk-proofs technology are emerging, but one of the challenges they face is the lack of a programmable circuit development tool for their business logic.


#### 2.Objective

To help address these issues, we set the below objective:

> Build a secure, scalable and privacy-preserving zk-rollup to accelerate web3 adoption.

#### 3.High-level architecture(to be updated)

![img1](./imgs/zkmove_arch.svg)

#### 4.A zero-knowledge Move VM under the hood
As a new generation of programming language for smart contract, Move ensures programming safety using its type checking, borrow checking and ownership mechanism. zkMove is full bytecode-compatible with Move and inherits the safety of Move.

zkMove VM circuit is built based on the Halo2 proof system. It’s assembled from multiple sub-circuits, including the execution circuit, the bytecode circuit, and the memory circuit, to verify the consistency and integrity of each step in execution trace.

zkMove VM is a type-safe zkVM. We create a uniform value word representation to efficiently express Values in the circuit. We also extract the type information from the bytecode to form a few fixed lookup tables. The innovations greatly reduce the complexity of the type-related constraints.

#### 5.Scaling and privacy solution rolled into one

zkMove combines public and private execution into a single rollup, providing seamless composability across private and public transactions. This design goal depends on two key components:

Client-side proving. For transactions that doesn't touch the public state, users can execute smart contracts and generate proof locally. Client-side proving not only preserves user’s privacy, but also makes the proving txn-level parallelizable.

Hybrid account and UTXO state model. It makes transactions such as token transfers only dependent on the user’s own state. Then the proof can be generated locally.


#### 6.Comparison with other zkRollups

(To be updated)

#### 7.New usages can be built on zkMove

(To be updated)

