# VM Circuit

## Overview

`VmCircuit` is one of the core components of zkMove. It is composed of several sub-circuits, each responsible for proving a specific aspect of MoveVM execution:

- **Execution Circuit** — proves that Move bytecode is executed correctly by MoveVM.
- **Poseidon Circuit** — proves that Poseidon hash computations are performed correctly.
- **State Circuit** *(planned)* — will prove that local state is updated correctly.

## Proof System

`VmCircuit` is built on the **Halo2-KZG** proof system. Halo2 supports recursive proof composition without significantly increasing proof size. Its PLONKish arithmetization provides custom gates and lookup arguments, offering the flexibility needed to construct complex arithmetic circuits.
