use crate::value::Value;
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use error::{RuntimeError, StatusCode, VmResult};
use ff::Field;

pub fn not<E, CS>(cs: &mut CS, operand: Value<E>) -> VmResult<Value<E>>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let ty = operand.ty();
    let value = match operand.value() {
        Some(v) => {
            let fr = if v.is_zero() {
                E::Fr::one()
            } else {
                E::Fr::zero()
            };
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
        || "constraint bool",
        |lc| lc + CS::one() - variable,
        |lc| lc + variable,
        |lc| lc,
    );

    cs.enforce(
        || "constraint",
        |lc| lc + CS::one() - &operand.lc::<CS>(),
        |lc| lc + CS::one(),
        |lc| lc + variable,
    );

    Value::new_variable(value, variable, ty)
}
