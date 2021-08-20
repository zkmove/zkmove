use crate::frame::Locals;
use crate::value::Value;
use crate::{bytecode::Instruction, error::VmResult, interpreter::Interpreter};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct LdTrue;

impl<E, CS> Instruction<E, CS> for LdTrue
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
        stack.push(Value::bool(true)?)
    }
}
