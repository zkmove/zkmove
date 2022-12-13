// Copyright (c) zkMove Authors

use halo2_proofs::arithmetic::FieldExt;

#[derive(Clone, Debug, Copy)]
pub enum EntryType {
    CALL = 0,
    RET,
}

// a struct to record the location of function call and return
#[derive(Clone, Debug, Copy)]
pub struct FunctionCall {
    pub type_: EntryType,
    pub module_index: u16,
    pub function_index: u16,
    pub pc: u16,
    pub next_module_index: u16,
    pub next_function_index: u16,
    pub next_pc: u16,
}

// convert FunctionCall into a vector of field values
impl<F: FieldExt> From<FunctionCall> for Vec<F> {
    fn from(func_call: FunctionCall) -> Vec<F> {
        vec![
            F::from_u128(func_call.type_ as u128),
            F::from_u128(func_call.module_index as u128),
            F::from_u128(func_call.function_index as u128),
            F::from_u128(func_call.pc as u128),
            F::from_u128(func_call.next_module_index as u128),
            F::from_u128(func_call.next_function_index as u128),
            F::from_u128(func_call.next_pc as u128),
        ]
    }
}
