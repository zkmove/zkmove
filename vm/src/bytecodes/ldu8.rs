use crate::value::Value;
use crate::{bytecode::Bytecode, error::VmResult, stack::Stack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct LdU8(pub u8);

impl<E, CS> Bytecode<E, CS> for LdU8
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, _cs: &mut CS, stack: &mut Stack<E>) -> VmResult<()> {
        stack.push(Value::u8(self.0)?)?;
        Ok(())
    }
}
