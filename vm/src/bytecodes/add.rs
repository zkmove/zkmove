use crate::frame::Locals;
use crate::value::Value;
use crate::{
    bytecode::Instruction, error::RuntimeError, error::StatusCode, error::VmResult,
    interpreter::Interpreter,
};
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use ff::Field;

pub struct Add;

impl<E, CS> Instruction<E, CS> for Add
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(
        &self,
        cs: &mut CS,
        _locals: &mut Locals<E>,
        interp: &mut Interpreter<E>,
    ) -> VmResult<()> {
        let stack = &mut interp.stack;
        let left = stack.pop()?;
        let right = stack.pop()?;

        let value = match (left.value(), right.value()) {
            (Some(a), Some(b)) => {
                let mut add_result = a;
                add_result.add_assign(&b);
                Some(add_result)
            }
            _ => None,
        };

        let variable = cs
            .alloc(
                || "variable",
                || value.ok_or(SynthesisError::AssignmentMissing),
            )
            .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))?;

        cs.enforce(
            || "constraint",
            |lc| lc + &left.lc::<CS>() + &right.lc::<CS>(),
            |lc| lc + CS::one(),
            |lc| lc + variable,
        );

        stack.push(Value::new_variable(value, variable)?)
    }
}
