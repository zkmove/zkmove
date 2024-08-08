// Copyright (c) zkMove Authors

use crate::chips::execution_chip::param::{set_word_capacity, word_capacity};
use crate::witness::arith_operations::ArithOperation;
use crate::witness::bytecode_table::BytecodeTable;
use crate::witness::call_trace_table::CallTraceTable;
use crate::witness::const_table::ConstantTable;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::function_calls::FunctionCall;
use crate::witness::input_type_elements::{GenericTypeMaterialization, InputTypeElementTableData};
use crate::witness::rw_operations::{RWOperation, RWOperations};
use crate::witness::type_instantiation_table::GenericTypeInstantiationTableData;
use aptos_move_witnesses::step_state::StageState;
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod arith_operations;
pub mod bytecode_table;
pub mod call_trace_table;
pub mod const_table;
pub mod exec_step;
pub mod execution_steps;
pub mod function_calls;
pub mod input_type_elements;
pub mod rw_operations;
pub mod type_instantiation_table;

pub const DEFAULT_MAX_FRAME_INDEX: usize = 16;
pub const DEFAULT_MAX_LOCALS_SIZE: usize = 16;
pub const DEFAULT_MAX_STACK_SIZE: usize = 256;
pub const DEFAULT_WORD_CAPACITY: usize = 8;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitConfig {
    pub max_step_row: Option<usize>,
    pub stack_ops_num: Option<usize>,
    pub locals_ops_num: Option<usize>,
    pub global_ops_num: Option<usize>,
    pub max_frame_index: usize,
    pub max_locals_size: usize,
    pub max_stack_size: usize,
    pub word_size: usize,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        CircuitConfig {
            max_step_row: None,
            stack_ops_num: None,
            locals_ops_num: None,
            global_ops_num: None,
            max_frame_index: DEFAULT_MAX_FRAME_INDEX,
            max_locals_size: DEFAULT_MAX_LOCALS_SIZE,
            max_stack_size: DEFAULT_MAX_STACK_SIZE,
            word_size: DEFAULT_WORD_CAPACITY,
        }
    }
}

impl CircuitConfig {
    pub fn max_step_row(mut self, max_row: Option<usize>) -> Self {
        self.max_step_row = max_row;
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

    pub fn max_stack_size(mut self, max_stack_size: usize) -> Self {
        self.max_stack_size = max_stack_size;
        self
    }

    pub fn word_size(mut self, word_capacity: Option<usize>) -> Self {
        if let Some(cap) = word_capacity {
            self.word_size = cap;
            // put it here to keep word_size and global word_cap in sync.
            set_word_capacity(cap);
        } else {
            set_word_capacity(DEFAULT_WORD_CAPACITY);
        }
        self
    }
}

#[derive(Clone, Default)]
pub struct ExecutionTrace {
    pub exec_steps: Vec<ExecutionStep>,
    pub rw_operations: Vec<RWOperation>,
    pub generic_types: Vec<GenericTypeMaterialization>,
}

#[derive(Clone, Default)]
pub struct Witness {
    pub exec_steps: Vec<ExecutionStep>,
    pub rw_operations: RWOperations,
    pub bytecode_table: BytecodeTable,
    pub constant_table: ConstantTable,
    pub func_call_table: Vec<FunctionCall>,
    pub arith_operations: Vec<ArithOperation>,
    pub call_trace_table: CallTraceTable,
    pub type_instantiations: GenericTypeInstantiationTableData,
    pub input_type_elements: InputTypeElementTableData,
    pub circuit_config: CircuitConfig,
}

impl Witness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exec_steps: Vec<ExecutionStep>,
        rw_operations: Vec<RWOperation>,
        bytecode_table: BytecodeTable,
        constant_table: ConstantTable,
        func_calls: Vec<FunctionCall>,
        arith_operations: Vec<ArithOperation>,
        call_trace_table: CallTraceTable,
        type_instantiations: GenericTypeInstantiationTableData,
        input_type_elements: InputTypeElementTableData,
        circuit_config: CircuitConfig,
    ) -> Self {
        Witness {
            exec_steps,
            rw_operations: RWOperations(rw_operations),
            bytecode_table,
            constant_table,
            func_call_table: func_calls,
            arith_operations,
            call_trace_table,
            type_instantiations,
            input_type_elements,
            circuit_config,
        }
    }
}

impl fmt::Debug for Witness {
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
        writeln!(f, "Constant table:")?;
        self.constant_table.0.iter().for_each(|constant| {
            writeln!(f, "{:?}", constant).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Function calls table:")?;
        self.func_call_table.iter().for_each(|call| {
            writeln!(f, "{:?}", call).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Arithmetic op table:")?;
        self.arith_operations.iter().for_each(|op| {
            writeln!(f, "{:?}", op).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Input type table:")?;
        self.input_type_elements.0.iter().for_each(|op| {
            writeln!(f, "{:?}", op).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Call trace table:")?;
        self.call_trace_table.0.iter().for_each(|op| {
            writeln!(f, "{:?}", op).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Type instantiation table:")?;
        self.type_instantiations.0.iter().for_each(|op| {
            writeln!(f, "{:?}", op).unwrap();
        });
        writeln!(f)?;
        writeln!(f, "Circuit Config:")?;
        writeln!(f, "{:?}", self.circuit_config).unwrap();
        writeln!(f, "Word_capacity: {:?}", word_capacity()).unwrap();
        Ok(())
    }
}

use crate::witness::exec_step::ExecStep;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CircuitConfigV2 {
    pub max_steps: Option<usize>,
}

#[derive(Clone, Default)]
pub struct ExecTrace {
    pub exec_steps: Vec<ExecStep>,
}

#[derive(Clone, Default)]
pub struct WitnessV2 {
    pub opcode_witnesses: Vec<StageState>,
    pub exec_steps: Vec<ExecStep>,
    pub bytecode_table: BytecodeTable,
    pub circuit_config: CircuitConfigV2,
}

impl WitnessV2 {
    pub fn new(
        opcode_witnesses: Vec<StageState>,
        exec_steps: Vec<ExecStep>,
        bytecode_table: BytecodeTable,
        circuit_config: CircuitConfigV2,
    ) -> Self {
        WitnessV2 {
            opcode_witnesses,
            exec_steps,
            bytecode_table,
            circuit_config,
        }
    }
}

pub mod to_field {
    use aptos_move_witnesses::step_state::SubIndex;
    use aptos_move_witnesses::SimpleValue;
    use types::Field;

    pub trait ToField<F: Field> {
        fn to_field(&self) -> F;
    }

    impl<F: Field> ToField<F> for SimpleValue {
        fn to_field(&self) -> F {
            todo!()
        }
    }

    impl<F: Field> ToField<F> for SubIndex {
        fn to_field(&self) -> F {
            todo!()
        }
    }
}
