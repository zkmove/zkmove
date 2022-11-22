// Copyright (c) zkMove Authors

use crate::frame::Frame;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use movelang::value::{Container, IndexedLocalsRef, IndexedRef, Reference, Struct, Value};
use std::rc::Rc;
use vm_circuit::witness::rw_operations::{RWOperation, StackOp, RW};

const EVAL_STACK_SIZE: usize = 256;
const CALL_STACK_SIZE: usize = 256;

pub struct EvalStack<F: FieldExt>(Vec<Value<F>>);

impl<F: FieldExt> EvalStack<F> {
    pub fn new() -> Self {
        EvalStack(vec![])
    }

    pub fn push(
        &mut self,
        value: Value<F>,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<()> {
        if self.0.len() < EVAL_STACK_SIZE {
            let stack_op = StackOp {
                address: self.0.len(),
                value: value.clone(),
                rw: RW::WRITE,
                gc: rw_operations.len(),
            };
            rw_operations.push(RWOperation::StackOp(stack_op));
            self.0.push(value);

            Ok(())
        } else {
            Err(RuntimeError::new(StatusCode::StackOverflow))
        }
    }

    pub fn pop(&mut self, rw_operations: &mut Vec<RWOperation<F>>) -> VmResult<Value<F>> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();

            let stack_op = StackOp {
                address: self.0.len(),
                value: value.clone(),
                rw: RW::READ,
                gc: rw_operations.len(),
            };
            rw_operations.push(RWOperation::StackOp(stack_op));

            Ok(value)
        }
    }

    pub fn popn(
        &mut self,
        n: u16,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Vec<Value<F>>> {
        let remaining_stack_size = self
            .0
            .len()
            .checked_sub(n as usize)
            .ok_or_else(|| RuntimeError::new(StatusCode::StackUnderflow))?;
        let values = self.0.split_off(remaining_stack_size);

        for (i, value) in values.iter().enumerate() {
            let stack_op = StackOp {
                address: self.0.len() - values.len() + 1 + i,
                value: value.clone(),
                rw: RW::READ,
                gc: rw_operations.len() + i,
            };
            rw_operations.push(RWOperation::StackOp(stack_op));
        }

        Ok(values)
    }

    pub fn pop_as_struct(
        &mut self,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Struct<F>> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();

            let stack_op = StackOp {
                address: self.0.len(),
                value: value.clone(),
                rw: RW::READ,
                gc: rw_operations.len(),
            };
            rw_operations.push(RWOperation::StackOp(stack_op));

            match value {
                Value::Container(Container::Struct(struct_)) => {
                    debug_assert_eq!(Rc::strong_count(&struct_), 1);
                    let fields = match Rc::try_unwrap(struct_) {
                        Ok(cell) => Ok(cell.into_inner()),
                        Err(v) => Err(RuntimeError::new(
                            StatusCode::UnknownInvariantViolationError,
                        )
                        .with_message(format!("moving value {:?} with dangling references", v))),
                    };
                    Ok(Struct::pack(fields?))
                }
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as struct", v))),
            }
        }
    }

    pub fn pop_as_reference(
        &mut self,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Reference<F>> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();

            let stack_op = StackOp {
                address: self.0.len(),
                value: value.clone(),
                rw: RW::READ,
                gc: rw_operations.len(),
            };
            rw_operations.push(RWOperation::StackOp(stack_op));

            match value {
                Value::ContainerRef(r) => Ok(Reference::ContainerRef(r)),
                Value::IndexedRef(r) => Ok(Reference::IndexedRef(r)),
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as reference", v))),
            }
        }
    }

    pub fn pop_struct_ref(
        &mut self,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<IndexedLocalsRef<F>> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();

            let stack_op = StackOp {
                address: self.0.len(),
                value: value.clone(),
                rw: RW::READ,
                gc: rw_operations.len(),
            };
            rw_operations.push(RWOperation::StackOp(stack_op));

            match value {
                Value::IndexedRef(r) => match r {
                    IndexedRef::IndexedLocalsRef(r) => Ok(r),
                    _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
                },
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as struct_ref", v))),
            }
        }
    }

    pub fn top(&self) -> Option<&Value<F>> {
        self.0.last()
    }

    pub fn size(&self) -> usize {
        self.0.len()
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

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl<F: FieldExt> Default for CallStack<F> {
    fn default() -> Self {
        Self::new()
    }
}
