use crate::value::Value;
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use error::{RuntimeError, StatusCode, VmResult};
use ff::Field;

pub fn mul<E, CS>(cs: &mut CS, left: Value<E>, right: Value<E>) -> VmResult<Value<E>>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let ty = left.ty();
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
        .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))?;

    cs.enforce(
        || "constraint",
        |lc| lc + &left.lc::<CS>(),
        |lc| lc + &right.lc::<CS>(),
        |lc| lc + variable,
    );

    Value::new_variable(value, variable, ty)
}
