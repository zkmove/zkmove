use crate::error::{RuntimeError, StatusCode, VmResult};
use crate::value::Value;
use bellman::pairing::Engine;

const OPERAND_STACK_SIZE: usize = 256;

pub struct Stack<E: Engine>(Vec<Value<E>>);

impl<E: Engine> Stack<E> {
    pub fn new() -> Self {
        Stack(vec![])
    }

    pub fn push(&mut self, value: Value<E>) -> VmResult<()> {
        if self.0.len() < OPERAND_STACK_SIZE {
            self.0.push(value);
            Ok(())
        } else {
            Err(RuntimeError::new(StatusCode::StackOverflow))
        }
    }

    pub fn pop(&mut self) -> VmResult<Value<E>> {
        if self.0.len() == 0 {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            Ok(self.0.pop().unwrap())
        }
    }

    pub fn top(&self) -> Option<&Value<E>> {
        self.0.last()
    }
}
