use crate::frame::Locals;
use crate::{bytecode::Instruction, error::VmResult, interpreter::Interpreter};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct Pop;

impl<E, CS> Instruction<E, CS> for Pop
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(
        &self,
        _cs: &mut CS,
        _locals: &mut Locals<E>,
        interp: &mut Interpreter<E>,
    ) -> VmResult<()> {
        let stack = &mut interp.stack;
        stack.pop()?;
        Ok(())
    }
}
