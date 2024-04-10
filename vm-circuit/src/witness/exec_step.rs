// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use movelang::value::Value;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum ValueFlag {
    #[default]
    Invalid,
    Simple,
    Header,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OpcodeContext {
    pub clk: u128,
    pub frame_index: u16, //CALL_STACK_SIZE_LIMIT = 1024
    pub module_index: u8,
    pub function_index: u8,
    pub pc: u16,
    pub sp: u16, //OPERAND_STACK_SIZE_LIMIT = 1024
    pub opcode: Opcode,
    pub aux0: Option<Value>,
    pub aux1: Option<Value>,
    pub step_counter: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct StackContext {
    pub stack_pop_index: u16,
    pub stack_pop_sub_index: u128,
    pub stack_pop_value: Option<Value>,
    pub stack_pop_value_flag: ValueFlag,
    pub stack_pop_version: u128,

    pub stack_push_index: u16,
    pub stack_push_sub_index: u128,
    pub stack_push_value: Option<Value>,
    pub stack_push_value_flag: ValueFlag,
    pub stack_push_version: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LocalContext {
    pub local_frame_index: u16,
    pub local_index: u16, //MAX_LOCALS = 256
    pub local_sub_index: u128,
    pub local_read_value: Option<Value>,
    pub local_read_value_flag: ValueFlag,
    pub local_read_version: u128,

    pub local_write_value: Option<Value>,
    pub local_write_value_flag: ValueFlag,
    pub local_write_version: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExecStep {
    opcode_context: OpcodeContext,
    stack_context: StackContext,
    local_context: LocalContext,
}

impl ExecStep {
    pub fn new(
        opcode_context: OpcodeContext,
        stack_context: StackContext,
        local_context: LocalContext,
    ) -> Self {
        ExecStep {
            opcode_context,
            stack_context,
            local_context,
        }
    }
}
