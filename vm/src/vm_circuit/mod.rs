// Copyright (c) zkMove Authors

pub mod chips;
pub mod circuit_inputs;
pub mod frame;
pub mod interpreter;
pub mod locals;
pub mod stack;

pub mod bytecode_circuit;
#[cfg(test)]
mod chip_tests;
pub mod execution_circuit;
pub mod memory_circuit;
