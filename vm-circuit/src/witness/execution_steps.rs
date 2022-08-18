use crate::chips::execution_chip::opcode::Opcode;
use proof_system::halo2_proofs::arithmetic::FieldExt;
use types::value::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionStep<F: FieldExt> {
    pub opcode: Opcode,
    pub pc: u16,
    pub stack_size: usize,
    pub call_index: usize,
    pub locals_index: usize,
    pub gc: usize, // global counter for stack, locals, state accesses
    pub module_index: u16,
    pub function_index: u16,
    pub auxiliary: Option<Value<F>>,
}
