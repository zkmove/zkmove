use crate::frame::Locals;
use crate::{bytecode::Instruction, error::VmResult, interpreter::Interpreter};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct Ret;

impl<E, CS> Instruction<E, CS> for Ret
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(
        &self,
        _cs: &mut CS,
        _locals: &mut Locals<E>,
        _interp: &mut Interpreter<E>,
    ) -> VmResult<()> {
        Ok(())
    }
}
