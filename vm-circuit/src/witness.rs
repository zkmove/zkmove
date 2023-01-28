// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::witness::arith_operations::ArithOperation;
use crate::witness::bytecode_table::BytecodeTable;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::function_calls::FunctionCall;
use crate::witness::rw_operations::{RWOperation, RWOperations};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use std::fmt;

pub mod arith_operations;
pub mod bytecode_table;
pub mod execution_steps;
pub mod function_calls;
pub mod rw_operations;

pub const DEFAULT_MAX_FRAME_INDEX: usize = 16;
pub const DEFAULT_MAX_LOCALS_SIZE: usize = 16;

#[derive(Clone, Debug)]
pub struct CircuitConfig {
    pub steps_num: Option<usize>,
    pub stack_ops_num: Option<usize>,
    pub locals_ops_num: Option<usize>,
    pub global_ops_num: Option<usize>,
    pub max_frame_index: usize,
    pub max_locals_size: usize,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        CircuitConfig {
            steps_num: None,
            stack_ops_num: None,
            locals_ops_num: None,
            global_ops_num: None,
            max_frame_index: DEFAULT_MAX_FRAME_INDEX,
            max_locals_size: DEFAULT_MAX_LOCALS_SIZE,
        }
    }
}

impl CircuitConfig {
    pub fn steps_num(mut self, steps_num: Option<usize>) -> Self {
        self.steps_num = steps_num;
        self
    }

    pub fn stack_ops_num(mut self, stack_ops_num: Option<usize>) -> Self {
        self.stack_ops_num = stack_ops_num;
        self
    }

    pub fn locals_ops_num(mut self, locals_ops_num: Option<usize>) -> Self {
        self.locals_ops_num = locals_ops_num;
        self
    }

    pub fn global_ops_num(mut self, global_ops_num: Option<usize>) -> Self {
        self.global_ops_num = global_ops_num;
        self
    }

    pub fn max_frame_index(mut self, max_frame_index: usize) -> Self {
        self.max_frame_index = max_frame_index;
        self
    }

    pub fn max_locals_size(mut self, max_locals_size: usize) -> Self {
        self.max_locals_size = max_locals_size;
        self
    }
}

#[derive(Clone, Default)]
pub struct Witness<F: FieldExt> {
    pub exec_steps: Vec<ExecutionStep<F>>,
    pub rw_operations: RWOperations<F>,
    pub bytecode_table: BytecodeTable,
    pub func_calls: Vec<FunctionCall>,
    pub arith_operations: Vec<ArithOperation>,
    pub circuit_config: CircuitConfig,
}

impl<F: FieldExt> Witness<F> {
    pub fn new(
        exec_steps: Vec<ExecutionStep<F>>,
        rw_operations: Vec<RWOperation<F>>,
        bytecode_table: BytecodeTable,
        func_calls: Vec<FunctionCall>,
        arith_operations: Vec<ArithOperation>,
        circuit_config: CircuitConfig,
    ) -> Self {
        Witness {
            exec_steps,
            rw_operations: RWOperations(rw_operations),
            bytecode_table,
            func_calls,
            arith_operations,
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
                frame_index: last.frame_index,
                locals_index: last.locals_index,
                gc: last.gc,
                module_index: last.module_index,
                function_index: last.function_index,
                auxiliary_1: last.auxiliary_1.clone(),
                auxiliary_2: last.auxiliary_2.clone(),
                auxiliary_3: last.auxiliary_3.clone(),
                auxiliary_4: last.auxiliary_4.clone(),
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
        let (sorted_stack_ops, sorted_locals_ops, sorted_global_ops) =
            self.rw_operations.clone().into();
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
        writeln!(f, "Sorted global operations:")?;
        sorted_global_ops.0.iter().for_each(|op| {
            writeln!(f, "{:?}", op).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Bytecode table:")?;
        self.bytecode_table.as_inner().iter().for_each(|bytecode| {
            writeln!(f, "{:?}", bytecode).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Function calls table:")?;
        self.func_calls.iter().for_each(|call| {
            writeln!(f, "{:?}", call).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Arithmetic op table:")?;
        self.arith_operations.iter().for_each(|op| {
            writeln!(f, "{:?}", op).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Circuit Config:")?;
        writeln!(f, "{:?}", self.circuit_config).unwrap();
        Ok(())
    }
}
