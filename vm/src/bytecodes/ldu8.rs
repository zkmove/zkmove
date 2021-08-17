use crate::value::Value;
use crate::{bytecode::Instruction, error::VmResult, stack::EvalStack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct LdU8(pub u8);

impl<E, CS> Instruction<E, CS> for LdU8
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, _cs: &mut CS, stack: &mut EvalStack<E>) -> VmResult<()> {
        stack.push(Value::u8(self.0)?)
    }
}
