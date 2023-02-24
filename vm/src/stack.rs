// Copyright (c) zkMove Authors

use crate::frame::Frame;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use movelang::account_address::AccountAddress;
use movelang::value::{
    AddressPath, Container, Index, Reference, Struct, StructRef, Value, ValueAddress,
};
use std::rc::Rc;
use vm_circuit::witness::rw_operations::{RWOperation, StackOp, RW};

const EVAL_STACK_SIZE: usize = 256;
const CALL_STACK_SIZE: usize = 256;

pub struct EvalStack<F: FieldExt>(Vec<Value<F>>);

impl<F: FieldExt> EvalStack<F> {
    pub fn new() -> Self {
        EvalStack(vec![])
    }

    pub fn emit_stack_ops_for_word(
        word: Vec<(AddressPath<F>, Value<F>)>,
        rw: RW,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) {
        for (address_path, val) in word {
            let stack_op = StackOp {
                address: *address_path.0.get(1).expect("address should not be None"),
                address_ext_0: *address_path
                    .0
                    .get(2)
                    .expect("address_ext_0 should not be None"),
                address_ext_1: *address_path
                    .0
                    .get(3)
                    .expect("address_ext_1 should not be None"),
                value: val,
                rw: rw.clone(),
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
            // Container in locals need to update address before bing pushed to stack
            let value = Value::update_address(value, ValueAddress::Stack(Index(self.0.len())));
            let word = value.flatten(ValueAddress::Stack(Index(self.0.len())))?;
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

            let word = value.flatten(ValueAddress::Stack(Index(self.0.len())))?;
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
            let word = value.flatten(ValueAddress::Stack(Index(remaining_stack_size + i)))?;
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);
        }

        Ok(values)
    }

    // return Struct and its word field count
    pub fn pop_as_struct(
        &mut self,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<(Struct<F>, usize)> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();

            let word = value.flatten(ValueAddress::Stack(Index(self.0.len())))?;
            let word_element_count = word.len();
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);

            match value {
                Value::Container(Container::Struct(_, struct_)) => {
                    debug_assert_eq!(Rc::strong_count(&struct_), 1);
                    let fields = match Rc::try_unwrap(struct_) {
                        Ok(cell) => Ok(cell.into_inner()),
                        Err(v) => Err(RuntimeError::new(
                            StatusCode::UnknownInvariantViolationError,
                        )
                        .with_message(format!("moving value {:?} with dangling references", v))),
                    };
                    Ok((Struct::pack(fields?), word_element_count))
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

            let word = value.flatten(ValueAddress::Stack(Index(self.0.len())))?;
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);

            match value {
                Value::ContainerRef(r) => Ok(Reference::ContainerRef(r)),
                Value::IndexedRef(r) => Ok(Reference::IndexedRef(r)),
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as reference", v))),
            }
        }
    }

    pub fn pop_as_struct_ref(
        &mut self,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<StructRef<F>> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();

            let word = value.flatten(ValueAddress::Stack(Index(self.0.len())))?;
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);

            match value {
                Value::ContainerRef(r) => Ok(StructRef(r)),
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as struct_ref", v))),
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

            let word = value.flatten(ValueAddress::Stack(Index(self.0.len())))?;
            Self::emit_stack_ops_for_word(word, RW::READ, rw_operations);

            match value {
                Value::Address(addr) => Ok(addr.account_address()),
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as account address", v))),
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
