use crate::{error::RuntimeError, stack::EvalStack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

// pub enum MoveBytecode {
//     LdU8(u8),
//     Pop,
//     Add,
// }

pub trait Instruction<E, CS>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    fn execute(&self, cs: &mut CS, stack: &mut EvalStack<E>) -> Result<(), RuntimeError>;
}
