use crate::value::Value;
use crate::vm_circuit::chips::execution_chips::opcode::Opcode;
use halo2_proofs::arithmetic::FieldExt;

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
