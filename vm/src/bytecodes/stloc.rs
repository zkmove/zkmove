use crate::{bytecode::Instruction, error::VmResult, frame::Locals, interpreter::Interpreter};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct StLoc(pub u8);

impl<E, CS> Instruction<E, CS> for StLoc
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(
        &self,
        _cs: &mut CS,
        locals: &mut Locals<E>,
        interp: &mut Interpreter<E>,
    ) -> VmResult<()> {
        // let locals = current_frame.locals();
        let value = interp.stack.pop()?;
        locals.store(self.0 as usize, value)
    }
}
