use crate::error::VmResult;
use crate::{bytecode::Bytecode, stack::Stack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct Interpreter<E: Engine> {
    stack: Stack<E>,
}

impl<E> Interpreter<E>
where
    E: Engine,
{
    pub fn new() -> Self {
        Self {
            stack: Stack::new(),
        }
    }

    pub fn run<CS>(&mut self, cs: &mut CS, code: &[Box<dyn Bytecode<E, CS>>]) -> VmResult<()>
    where
        CS: ConstraintSystem<E>,
    {
        for (i, instruction) in code.iter().enumerate() {
            cs.push_namespace(|| format!("#{}", i));
            instruction.execute(cs, &mut self.stack)?;
            cs.pop_namespace();
        }
        Ok(())
    }

    pub fn stack(&self) -> &Stack<E> {
        &self.stack
    }
}
