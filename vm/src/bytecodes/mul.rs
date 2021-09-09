use crate::frame::Locals;
use crate::value::Value;
use crate::{bytecode::Instruction, interpreter::Interpreter};
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use error::{RuntimeError, StatusCode, VmResult};
use ff::Field;

pub struct Mul;

impl<E, CS> Instruction<E, CS> for Mul
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

        stack.push(Value::new_variable(value, variable, ty)?)
    }
}
