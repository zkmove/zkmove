use crate::stack::{EvalStack, CallStack};
use bellman::pairing::Engine;

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
}
