# Project Structure

The project is structured as follows:
.
├── cli/
├── functional-tests/               # integration tests
├── spec/
├── third-party/
│   ├── circuit-tool/               # circuit utilities (from zkevm)
│   ├── gadgets/                    # generic gadgets (from zkevm)
│   ├── halo2/                      # halo2 backend wrappers
│   └── ...
├── types/                          # core VM types
├── vm-circuit/                     # VM circuit
├── witness/                        # witness generation
└── ...