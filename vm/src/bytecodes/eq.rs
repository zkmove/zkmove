use crate::{
    bytecode::Instruction, error::RuntimeError, error::StatusCode, error::VmResult, frame::Locals,
    interpreter::Interpreter, value::Value,
};
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use ff::Field;

pub struct Eq;

impl<E, CS> Instruction<E, CS> for Eq
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
                let fr = if a == b { E::Fr::one() } else { E::Fr::zero() };
                Some(fr)
            }
            _ => None,
        };

        let variable = cs
            .alloc(
                || "variable",
                || value.ok_or(SynthesisError::AssignmentMissing),
            )
            .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))?;

        // (1 - x) * x = 0
        cs.enforce(
            || "constraint",
            |lc| lc + CS::one() - variable,
            |lc| lc + variable,
            |lc| lc,
        );

        stack.push(Value::new_variable(value, variable)?)
    }
}
