// Copyright (c) zkMove Authors

use halo2_proofs::arithmetic::FieldExt;

#[derive(Clone, Debug, Copy)]
pub struct FunctionCall {
    pub module_index: u16, //caller's module index
    pub function_index: u16, //caller's function index
    pub pc: u16,
    pub callee_module_index: u16,
    pub callee_function_index: u16,
}

// convert FunctionCall into a vector of field values
impl<F: FieldExt> From<FunctionCall> for Vec<F> {
    fn from(func_call: FunctionCall) -> Vec<F> {
        vec![
            F::from_u128(func_call.module_index as u128),
            F::from_u128(func_call.function_index as u128),
            F::from_u128(func_call.pc as u128),
            F::from_u128(func_call.callee_module_index as u128),
            F::from_u128(func_call.callee_function_index as u128),
        ]
    }
}