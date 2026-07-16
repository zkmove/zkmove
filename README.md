## zkMove

Technically, **zkMove** is a secure, high-performance zkVM that proves the execution of Move functions. It empowers Move smart contracts to access and process private data in a fully programmable and trustless manner.

From a product perspective, zkMove is both a middleware and an SDK — one that Move developers can use to build privacy-preserving decentralized applications without deep cryptographic expertise.

## Project Structure

The project is structured as follows:
```
.
├── cli/                            # command-line interface for zkMove
├── docs/                           # design documents
├── functional-tests/               # integration tests
├── spec/                           # specification of zkMove circuits
├── third-party/
│   ├── circuit-tool/               # circuit utilities (from zkevm)
│   ├── gadgets/                    # generic gadgets (from zkevm)
│   ├── halo2/                      # halo2 backend wrappers
│   └── ...
├── types/                          # core VM types
├── vm-circuit/                     # VM circuit
├── witness/                        # witness generation
└── ...
```

## Documents

see [User Guide](https://www.zkmove.net/document/user/setup-dev-environment/) for a step-by-step tutorial on how to create a zkMove circuit, generate a proof, and verify it on-chain.

see [Litepaper](https://www.zkmove.net/document/litepaper/abstract/) for an in-depth technical overview of zkMove's design and architecture.

## License

zkMove is licensed as [Apache 2.0](./LICENSE).