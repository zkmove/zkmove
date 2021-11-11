use crate::value::Value;
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use error::{RuntimeError, StatusCode, VmResult};
use ff::Field;

pub fn eq<E, CS>(cs: &mut CS, left: Value<E>, right: Value<E>) -> VmResult<Value<E>>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let ty = left.ty();
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

    Value::new_variable(value, variable, ty)
}
