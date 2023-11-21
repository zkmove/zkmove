// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use movelang::value::Value;
use types::Field;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionStep<F: Field> {
    pub context_id: u128,
    pub opcode: Opcode,
    pub pc: u16,
    pub stack_size: usize,
    pub frame_index: usize,
    pub locals_index: usize,
    pub gc: usize, // global counter for stack, locals, state accesses
    pub module_index: u16,
    pub function_index: u16,
    pub auxiliary_1: Option<Value<F>>,
    pub auxiliary_2: Option<Value<F>>,
    pub auxiliary_3: Option<Value<F>>,
    pub auxiliary_4: Option<Value<F>>,
    pub auxiliary_5: Option<Value<F>>,
    pub data: Option<ExecutionData>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionData {
    CallGeneric(GenericTypeData),
    StorageOp(GenericTypeData),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenericTypeData {
    pub generic_types: Vec<MaterializedTypeInfo>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MaterializedTypeInfo {
    pub inst_ty_pos: u128,
    pub inst_ty_pos_max: u128,
    pub referred_param_index: u16,

    pub ty_arg_pos: u128,
    pub ty_arg_module: u64,
    pub ty_arg_name: u16,
}
