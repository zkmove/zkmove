# zkMove Design Documentation

This directory contains design documents for the core components of zkMove.

---

## Table of Contents

### 1. [VM Circuit](vm-circuit.md)
- [Overview](vm-circuit.md#overview)
- [Proof System](vm-circuit.md#proof-system)

### 2. [Execution Circuit](execution-circuit.md)
- [Overview](execution-circuit.md#overview)
- [Circuit Structure](execution-circuit.md#circuit-structure)
  - [Shared Cells](execution-circuit.md#shared-cells)
  - [Instruction-Specific Cells](execution-circuit.md#instruction-specific-cells)
  - [Multi-Row Instruction Layout](execution-circuit.md#multi-row-instruction-layout)

### 3. [Memory Consistency Checking](memory-consistency-checking.md)
- [Algorithm](memory-consistency-checking.md#algorithm)
  - [Applying MCC to the Stack](memory-consistency-checking.md#applying-mcc-to-the-stack)
- [Implementation](memory-consistency-checking.md#implementation)
- [References](memory-consistency-checking.md#references)

### 4. [Value Representation and Type Checking](value-representation.md)
- [Types in Move](value-representation.md#types-in-move)
- [Circuit Representation of Types](value-representation.md#circuit-representation-of-types)
  - [Representing Simple Values](value-representation.md#representing-simple-values)
  - [Representing Complex Values](value-representation.md#representing-complex-values)
  - [Representation of References](value-representation.md#representation-of-references)
- [Type Checking](value-representation.md#type-checking)
  - [Static Type Checking](value-representation.md#static-type-checking)
  - [Dynamic Type Checking](value-representation.md#dynamic-type-checking)
- [Creating and Modifying Complex Values](value-representation.md#creating-and-modifying-complex-values)
- [Dynamic Vectors](value-representation.md#dynamic-vectors)
- [Reading and Writing Complex Values](value-representation.md#reading-and-writing-complex-values)
