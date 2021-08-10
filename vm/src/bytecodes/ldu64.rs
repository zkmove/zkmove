use crate::value::Value;
use crate::{bytecode::Bytecode, error::VmResult, stack::Stack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct LdU64(pub u64);

impl<E, CS> Bytecode<E, CS> for LdU64
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, _cs: &mut CS, stack: &mut Stack<E>) -> VmResult<()> {
        stack.push(Value::u64(self.0)?)
    }
}
