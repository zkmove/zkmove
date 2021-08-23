use crate::{frame::Locals, value::Value, bytecode::Instruction, error::VmResult, error::RuntimeError, error::StatusCode, interpreter::Interpreter};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct Eq;

impl<E, CS> Instruction<E, CS> for Eq
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
        let left = stack
            .pop()?
            .value()
            .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
        let right = stack
            .pop()?
            .value()
            .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
        stack.push(Value::bool(left == right)?)
    }
}
