use crate::value::Value;
use crate::{bytecode::Bytecode, error::VmResult, stack::Stack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct LdU128(pub u128);

impl<E, CS> Bytecode<E, CS> for LdU128
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, _cs: &mut CS, stack: &mut Stack<E>) -> VmResult<()> {
        stack.push(Value::u128(self.0)?)
    }
}
