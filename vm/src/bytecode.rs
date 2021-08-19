use crate::{error::RuntimeError, frame::Locals, interpreter::Interpreter};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub trait Instruction<E, CS>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(
        &self,
        cs: &mut CS,
        locals: &mut Locals<E>,
        interp: &mut Interpreter<E>,
    ) -> Result<(), RuntimeError>;
}
