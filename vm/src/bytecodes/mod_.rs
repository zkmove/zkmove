use crate::frame::Locals;
use crate::value::Value;
use crate::{bytecode::Instruction, interpreter::Interpreter};
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use error::{RuntimeError, StatusCode, VmResult};
use movelang::value::{div, rem, MoveValue};
use std::convert::TryInto;

pub struct Mod;

impl<E, CS> Instruction<E, CS> for Mod
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
        let right = stack.pop()?;
        let left = stack.pop()?;
        let ty = left.ty();

        let num_l: Option<MoveValue> = left.clone().try_into()?;
        let num_r: Option<MoveValue> = right.clone().try_into()?;

        let (quotient, remainder) = match (num_l, num_r) {
            (Some(l), Some(r)) => {
                let quo: Value<E> = div(l.clone(), r.clone())?.try_into()?;
                let rem: Value<E> = rem(l, r)?.try_into()?;
                (quo.value(), rem.value())
            }
            _ => (None, None),
        };

        let quotient_variable = cs
            .alloc(
                || "quotient_variable",
                || quotient.ok_or(SynthesisError::AssignmentMissing),
            )
            .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))?;

        let remainder_variable = cs
            .alloc(
                || "remainder_variable",
                || remainder.ok_or(SynthesisError::AssignmentMissing),
            )
            .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))?;

        cs.enforce(
            || "constraint",
            |lc| lc + quotient_variable,
            |lc| lc + &right.lc::<CS>(),
            |lc| lc + &left.lc::<CS>() - remainder_variable,
        );

        stack.push(Value::new_variable(remainder, remainder_variable, ty)?)
    }
}
