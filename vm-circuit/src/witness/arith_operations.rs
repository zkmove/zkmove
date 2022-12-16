// Copyright (c) zkMove Authors

use halo2_proofs::arithmetic::FieldExt;

/// The arithmetic operation Add, Sub, Mul, Div, Mod can be applied to
/// different types of unsigned integers. The type information is discarded
/// after execution, and we need to record the type for use in the step chip.

// a struct to record the value type of arithmetic operations
#[derive(Clone, Debug, Copy)]
pub struct ArithOperation {
    pub module_index: u16,
    pub function_index: u16,
    pub pc: u16,
    pub num_of_bytes: usize, // number of bytes of operand
}

// convert ArithOperation into a vector of field values
impl<F: FieldExt> From<&ArithOperation> for Vec<F> {
    fn from(arith_op: &ArithOperation) -> Vec<F> {
        vec![
            F::from_u128(arith_op.module_index as u128),
            F::from_u128(arith_op.function_index as u128),
            F::from_u128(arith_op.pc as u128),
            F::from_u128(arith_op.num_of_bytes as u128),
        ]
    }
}
