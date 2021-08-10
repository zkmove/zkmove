use crate::{
    bytecode::Bytecode, error::RuntimeError, error::StatusCode, error::VmResult, stack::Stack,
};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct Pop;

impl<E, CS> Bytecode<E, CS> for Pop
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, _cs: &mut CS, stack: &mut Stack<E>) -> VmResult<()> {
        stack.pop();
        Ok(())
    }
}
