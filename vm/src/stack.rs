use crate::frame::Frame;
use crate::value::Value;
use error::{RuntimeError, StatusCode, VmResult};
use halo2::arithmetic::FieldExt;

const EVAL_STACK_SIZE: usize = 256;
const CALL_STACK_SIZE: usize = 256;

pub struct EvalStack<F: FieldExt>(Vec<Value<F>>);

impl<F: FieldExt> EvalStack<F> {
    pub fn new() -> Self {
        EvalStack(vec![])
    }

    pub fn push(&mut self, value: Value<F>) -> VmResult<()> {
        if self.0.len() < EVAL_STACK_SIZE {
            self.0.push(value);
            Ok(())
        } else {
            Err(RuntimeError::new(StatusCode::StackOverflow))
        }
    }

    pub fn pop(&mut self) -> VmResult<Value<F>> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            Ok(self.0.pop().unwrap())
        }
    }

    pub fn top(&self) -> Option<&Value<F>> {
        self.0.last()
    }
}

impl<F: FieldExt> Default for EvalStack<F> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CallStack<F: FieldExt>(Vec<Frame<F>>);

impl<F: FieldExt> CallStack<F> {
    pub fn new() -> Self {
        CallStack(vec![])
    }

    pub fn push(&mut self, frame: Frame<F>) -> VmResult<()> {
        if self.0.len() < CALL_STACK_SIZE {
            self.0.push(frame);
            Ok(())
        } else {
            Err(RuntimeError::new(StatusCode::StackOverflow))
        }
    }

    pub fn pop(&mut self) -> Option<Frame<F>> {
        if self.0.is_empty() {
            None
        } else {
            Some(self.0.pop().unwrap())
        }
    }

    pub fn top(&mut self) -> Option<&mut Frame<F>> {
        self.0.last_mut()
    }
}

impl<F: FieldExt> Default for CallStack<F> {
    fn default() -> Self {
        Self::new()
    }
}
