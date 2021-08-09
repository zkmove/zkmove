use crate::{error::RuntimeError, stack::Stack};
use bellman::pairing::Engine;

// pub enum MoveBytecode {
//     LdU8(u8),
//     Pop,
//     Add,
// }

pub trait Bytecode<E>
where
    E: Engine,
{
    fn execute(&self, stack: &mut Stack<E>) -> Result<(), RuntimeError>;
}
