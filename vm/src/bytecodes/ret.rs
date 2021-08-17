use crate::{bytecode::Bytecode, error::VmResult, stack::Stack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct Ret;

impl<E, CS> Bytecode<E, CS> for Ret
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, _cs: &mut CS, _stack: &mut Stack<E>) -> VmResult<()> {
        Ok(())
    }
}
