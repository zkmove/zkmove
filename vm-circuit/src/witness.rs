// Copyright (c) zkMove Authors

use crate::witness::bytecode_table::BytecodeTable;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperation, RWOperations};
use halo2_proofs::arithmetic::FieldExt;
use std::fmt;

pub mod bytecode_table;
pub mod execution_steps;
pub mod rw_operations;

#[derive(Clone, Default)]
pub struct Witness<F: FieldExt> {
    pub exec_steps: Vec<ExecutionStep<F>>,
    pub rw_operations: RWOperations<F>,
    pub bytecode_table: BytecodeTable,
}

impl<F: FieldExt> Witness<F> {
    pub fn new(
        exec_steps: Vec<ExecutionStep<F>>,
        rw_operations: Vec<RWOperation<F>>,
        bytecode_table: BytecodeTable,
    ) -> Self {
        Witness {
            exec_steps,
            rw_operations: RWOperations(rw_operations),
            bytecode_table,
        }
    }
}

impl<F: FieldExt> fmt::Debug for Witness<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "Execution steps:")?;
        self.exec_steps.iter().enumerate().for_each(|(i, step)| {
            writeln!(f, "{}: {:?}", i, step).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Read/Write operations:")?;
        self.rw_operations.0.iter().for_each(|op| {
            writeln!(f, "{:?}", op).unwrap();
        });
        writeln!(f)?;
        let (sorted_stack_ops, sorted_locals_ops) = self.rw_operations.clone().into();
        writeln!(f, "Sorted stack operations:")?;
        sorted_stack_ops.0.iter().for_each(|op| {
            writeln!(f, "{:?}", op).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Sorted locals operations:")?;
        sorted_locals_ops.0.iter().for_each(|op| {
            writeln!(f, "{:?}", op).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Bytecode table:")?;
        self.bytecode_table.as_inner().iter().for_each(|bytecode| {
            writeln!(f, "{:?}", bytecode).unwrap();
        });
        Ok(())
    }
}
