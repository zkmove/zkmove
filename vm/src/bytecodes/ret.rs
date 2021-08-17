use crate::{bytecode::Instruction, error::VmResult, stack::EvalStack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct Ret;

impl<E, CS> Instruction<E, CS> for Ret
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, _cs: &mut CS, _stack: &mut EvalStack<E>) -> VmResult<()> {
        Ok(())
    }
}
