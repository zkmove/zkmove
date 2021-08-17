use crate::value::Value;
use crate::{bytecode::Instruction, error::VmResult, stack::EvalStack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct LdU128(pub u128);

impl<E, CS> Instruction<E, CS> for LdU128
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, _cs: &mut CS, stack: &mut EvalStack<E>) -> VmResult<()> {
        stack.push(Value::u128(self.0)?)
    }
}
