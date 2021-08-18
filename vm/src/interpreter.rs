use crate::bytecode::Instruction;
use crate::error::VmResult;
use crate::stack::{CallStack, EvalStack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;

pub struct Interpreter<E: Engine> {
    pub stack: EvalStack<E>,
    pub frames: CallStack<E>,
}

impl<E> Interpreter<E>
where
    E: Engine,
{
    pub fn new() -> Self {
        Self {
            stack: EvalStack::new(),
            frames: CallStack::new(),
        }
    }

    pub fn stack(&self) -> &EvalStack<E> {
        &self.stack
    }

    pub fn run_test<CS>(
        &mut self,
        cs: &mut CS,
        code: &[Box<dyn Instruction<E, CS>>],
    ) -> VmResult<()>
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
}
