use crate::{error::RuntimeError, stack::Stack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

// pub enum MoveBytecode {
//     LdU8(u8),
//     Pop,
//     Add,
// }

pub trait Bytecode<E, CS>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, cs: &mut CS, stack: &mut Stack<E>) -> Result<(), RuntimeError>;
}
