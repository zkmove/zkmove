use crate::value::Value;
use crate::{
    bytecode::Instruction, error::RuntimeError, error::StatusCode, error::VmResult, stack::EvalStack,
};
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use ff::Field;

pub struct Mul;

impl<E, CS> Instruction<E, CS> for Mul
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, cs: &mut CS, stack: &mut EvalStack<E>) -> VmResult<()> {
        let left = stack.pop()?;
        let right = stack.pop()?;

        let value = match (left.value(), right.value()) {
            (Some(a), Some(b)) => {
                let mut mul_result = a;
                mul_result.mul_assign(&b);
                Some(mul_result)
            }
            _ => None,
        };

        let variable = cs
            .alloc(
                || "variable",
                || value.ok_or(SynthesisError::AssignmentMissing),
            )
            .map_err(|_| RuntimeError::new(StatusCode::SynthesisError))?;

        cs.enforce(
            || "constraint",
            |lc| lc + &left.lc::<CS>(),
            |lc| lc + &right.lc::<CS>(),
            |lc| lc + variable,
        );

        stack.push(Value::new_variable(value, variable)?)
    }
}
