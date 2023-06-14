// Copyright (c) zkMove Authors

use crate::frame::Frame;
use error::{RuntimeError, StatusCode, VmResult};
use fields::FieldExt;
use movelang::account_address::AccountAddress;
use movelang::value::{
    Container, ContainerValue, LocatedValue, Reference, StackLocation, Value, ValueLocation,
    VectorRef,
};
use movelang::word::LocatedWord;
use std::rc::Rc;
use vm_circuit::witness::rw_operations::{RWOperation, StackOp, RW};

const EVAL_STACK_SIZE: usize = 256;
const CALL_STACK_SIZE: usize = 256;

pub struct EvalStack<F: FieldExt>(Vec<Value<F>>);

impl<F: FieldExt> EvalStack<F> {
    pub fn new() -> Self {
        EvalStack(vec![])
    }

    #[allow(clippy::type_complexity)]
    pub fn emit_stack_ops_for_word(
        word: LocatedWord<F>,
        rw: RW,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) {
        for (address_path, val) in word.0 {
            let stack_op = StackOp {
                address: *address_path.0.get(1).expect("address should not be None") as usize,
                address_ext_0: address_path.addr_ext(),
                address_ext_1: 0_usize,
                value: Some(val),
                rw,
                gc: rw_operations.len(),
            };
            rw_operations.push(RWOperation::StackOp(stack_op));
        }
    }

    pub fn push(
        &mut self,
        value: Value<F>,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<()> {
        if self.0.len() < EVAL_STACK_SIZE {
            let word: LocatedWord<F> = LocatedValue(
                ValueLocation::Stack(StackLocation {
                    stack_index: self.0.len(),
                }),
                &value,
            )
            .into();
            Self::emit_stack_ops_for_word(word, RW::WRITE, rw_operations);

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
            let word: LocatedWord<F> = LocatedValue(
                ValueLocation::Stack(StackLocation {
                    stack_index: self.0.len(),
                }),
                &value,
            )
            .into();
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);

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
            let word: LocatedWord<F> = LocatedValue(
                ValueLocation::Stack(StackLocation {
                    stack_index: (remaining_stack_size + i),
                }),
                value,
            )
            .into();
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);
        }

        Ok(values)
    }

    // return values of a container and its word field count
    pub fn pop_as_container(
        &mut self,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<(ContainerValue<F>, usize)> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();
            let loc = StackLocation {
                stack_index: self.0.len(),
            };
            let word: LocatedWord<F> = LocatedValue(ValueLocation::Stack(loc), &value).into();
            let word_element_count = word.0.len();
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);

            match value {
                Value::Container(Container(struct_)) => {
                    debug_assert_eq!(Rc::strong_count(&struct_), 1);
                    let fields = match Rc::try_unwrap(struct_) {
                        Ok(cell) => Ok(cell.into_inner()),
                        Err(v) => Err(RuntimeError::new(
                            StatusCode::UnknownInvariantViolationError,
                        )
                        .with_message(format!("moving value {:?} with dangling references", v))),
                    };
                    Ok((ContainerValue::pack(fields?), word_element_count))
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

            let word: LocatedWord<F> = LocatedValue(
                ValueLocation::Stack(StackLocation {
                    stack_index: self.0.len(),
                }),
                &value,
            )
            .into();
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);

            match value {
                Value::GlobalRef(r) => Ok(Reference::GlobalRef(r)),
                Value::LocalRef(r) => Ok(Reference::LocalRef(r)),
                Value::IndexedRef(r) => Ok(Reference::IndexedRef(r)),
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as reference", v))),
            }
        }
    }

    pub fn pop_as_vector_ref(
        &mut self,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<VectorRef<F>> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();

            let word: LocatedWord<F> = LocatedValue(
                ValueLocation::Stack(StackLocation {
                    stack_index: self.0.len(),
                }),
                &value,
            )
            .into();
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);

            match value {
                Value::LocalRef(r) => Ok(VectorRef::LocalRef(r)),
                Value::IndexedRef(r) => Ok(VectorRef::IndexedRef(r)),
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as reference", v))),
            }
        }
    }

    pub fn pop_as_account_address(
        &mut self,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<AccountAddress<F>> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();
            let v_loc = StackLocation {
                stack_index: self.0.len(),
            };
            let word: LocatedWord<F> = LocatedValue(ValueLocation::Stack(v_loc), &value).into();
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);

            match value {
                Value::Address(addr) => Ok(addr),
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as account address", v))),
            }
        }
    }

    pub fn pop_as_u64(&mut self, rw_operations: &mut Vec<RWOperation<F>>) -> VmResult<u64> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();
            let v_loc = StackLocation {
                stack_index: self.0.len(),
            };
            let word: LocatedWord<F> = LocatedValue(ValueLocation::Stack(v_loc), &value).into();
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);

            match value {
                Value::U64(v) => Ok(v.0.get_lower_128() as u64),
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as U64", v))),
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
