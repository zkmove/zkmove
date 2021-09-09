use crate::{bytecode::Instruction, frame::Locals, interpreter::Interpreter};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;
use error::VmResult;

pub struct MoveLoc(pub u8);

impl<E, CS> Instruction<E, CS> for MoveLoc
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
        let value = locals.move_local(self.0 as usize)?;
        interp.stack.push(value)
    }
}
