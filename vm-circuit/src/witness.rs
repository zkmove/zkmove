// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::witness::bytecode_table::BytecodeTable;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperation, RWOperations};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use std::fmt;

pub mod bytecode_table;
pub mod execution_steps;
pub mod rw_operations;

#[derive(Clone, Default)]
pub struct CircuitConfig {
    pub steps_num: Option<usize>,
    pub stack_ops_num: Option<usize>,
    pub locals_ops_num: Option<usize>,
}

#[derive(Clone, Default)]
pub struct Witness<F: FieldExt> {
    pub exec_steps: Vec<ExecutionStep<F>>,
    pub rw_operations: RWOperations<F>,
    pub bytecode_table: BytecodeTable,
    pub circuit_config: CircuitConfig,
}

impl<F: FieldExt> Witness<F> {
    pub fn new(
        exec_steps: Vec<ExecutionStep<F>>,
        rw_operations: Vec<RWOperation<F>>,
        bytecode_table: BytecodeTable,
        circuit_config: CircuitConfig,
    ) -> Self {
        Witness {
            exec_steps,
            rw_operations: RWOperations(rw_operations),
            bytecode_table,
            circuit_config,
        }
    }

    // If the number of steps is less than a given steps number, fill with nop.
    // This happened when an execution path is not fixed, for example, if there
    // is loop in the code.
    pub fn process_exec_steps(&self) -> Result<Vec<ExecutionStep<F>>, Error> {
        let mut exec_steps = self.exec_steps.clone();
        if let Some(steps_number) = self.circuit_config.steps_num {
            let last = exec_steps.last().ok_or_else(|| {
                error!("failed to get the last exec step");
                Error::Synthesis
            })?;

            let nop = ExecutionStep {
                opcode: Opcode::Nop,
                pc: last.pc,
                stack_size: last.stack_size,
                call_index: last.call_index,
                locals_index: last.locals_index,
                gc: last.gc,
                module_index: last.module_index,
                function_index: last.function_index,
                auxiliary: last.auxiliary.clone(),
            };

            while exec_steps.len() < steps_number {
                exec_steps.insert(exec_steps.len() - 1, nop.clone());
            }
        }
        Ok(exec_steps)
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
