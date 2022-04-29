// Copyright (c) zkMove Authors

pub mod chips;
pub mod circuit_inputs;
pub mod frame;
pub mod interpreter;
pub mod locals;
pub mod stack;

#[cfg(test)]
mod chip_tests;
pub mod code_chip;
pub mod execution_chip;
pub mod memory_chip;

pub mod vm_circuit;
