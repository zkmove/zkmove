use crate::{bytecode::Instruction, error::VmResult, stack::EvalStack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct Pop;

impl<E, CS> Instruction<E, CS> for Pop
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, _cs: &mut CS, stack: &mut EvalStack<E>) -> VmResult<()> {
        stack.pop()?;
        Ok(())
    }
}
