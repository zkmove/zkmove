use crate::value::Value;
use crate::{
    bytecode::Bytecode, error::RuntimeError, error::StatusCode, error::VmResult, stack::Stack,
};
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use ff::Field;

pub struct Sub;

impl<E, CS> Bytecode<E, CS> for Sub
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, cs: &mut CS, stack: &mut Stack<E>) -> VmResult<()> {
        let left = stack.pop()?;
        let right = stack.pop()?;

        let value = match (left.value(), right.value()) {
            (Some(a), Some(b)) => {
                let mut sub_result = a;
                sub_result.sub_assign(&b);
                Some(sub_result)
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
            |lc| lc + &left.lc::<CS>() - &right.lc::<CS>(),
            |lc| lc + CS::one(),
            |lc| lc + variable,
        );

        stack.push(Value::new_variable(value, variable)?)
    }
}
