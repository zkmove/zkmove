// Copyright (c) zkMove Authors

use crate::frame::Frame;
use error::{RuntimeError, StatusCode, VmResult};
use movelang::account_address::AccountAddress;
use movelang::value::{
    Container, ContainerValue, LocatedValue, Reference, StackLocation, Value, ValueLocation,
    VectorRef,
};
use movelang::value_ext::LocatedFlattenedValue;
use std::rc::Rc;
use vm_circuit::witness::rw_operations::{RWOperation, StackOp, RW};

const EVAL_STACK_SIZE: usize = 256;
const CALL_STACK_SIZE: usize = 256;

pub struct EvalStack(Vec<Value>);

impl EvalStack {
    pub fn new() -> Self {
        EvalStack(vec![])
    }

    #[allow(clippy::type_complexity)]
    pub fn emit_stack_ops(
        flattened_value: LocatedFlattenedValue,
        rw: RW,
        rw_operations: &mut Vec<RWOperation>,
    ) {
        for (address_path, val) in flattened_value.0 {
            let stack_op = StackOp {
                address: *address_path.0.get(1).expect("address should not be None") as usize,
                address_ext: address_path.addr_ext(),
                value: Some(val),
                rw,
                gc: rw_operations.len(),
            };
            rw_operations.push(RWOperation::StackOp(stack_op));
        }
    }

    pub fn push(&mut self, value: Value, rw_operations: &mut Vec<RWOperation>) -> VmResult<()> {
        if self.0.len() < EVAL_STACK_SIZE {
            let flattened_value: LocatedFlattenedValue = LocatedValue(
                ValueLocation::Stack(StackLocation {
                    stack_index: self.0.len(),
                }),
                &value,
            )
            .into();
            Self::emit_stack_ops(flattened_value, RW::WRITE, rw_operations);

            self.0.push(value);
            Ok(())
        } else {
            Err(RuntimeError::new(StatusCode::StackOverflow))
        }
    }

    pub fn pop(&mut self, rw_operations: &mut Vec<RWOperation>) -> VmResult<Value> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();
            let flattened_value: LocatedFlattenedValue = LocatedValue(
                ValueLocation::Stack(StackLocation {
                    stack_index: self.0.len(),
                }),
                &value,
            )
            .into();
            Self::emit_stack_ops(flattened_value, RW::READ, rw_operations);

            Ok(value)
        }
    }

    pub fn popn(&mut self, n: u16, rw_operations: &mut Vec<RWOperation>) -> VmResult<Vec<Value>> {
        let remaining_stack_size = self
            .0
            .len()
            .checked_sub(n as usize)
            .ok_or_else(|| RuntimeError::new(StatusCode::StackUnderflow))?;
        let values = self.0.split_off(remaining_stack_size);

        for (i, value) in values.iter().enumerate() {
            let flattened_value: LocatedFlattenedValue = LocatedValue(
                ValueLocation::Stack(StackLocation {
                    stack_index: (remaining_stack_size + i),
                }),
                value,
            )
            .into();
            Self::emit_stack_ops(flattened_value, RW::READ, rw_operations);
        }

        Ok(values)
    }

    // return values of a container and its flattened_value field count
    pub fn pop_as_container(
        &mut self,
        rw_operations: &mut Vec<RWOperation>,
    ) -> VmResult<(ContainerValue, usize)> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();
            let loc = StackLocation {
                stack_index: self.0.len(),
            };
            let flattened_value: LocatedFlattenedValue =
                LocatedValue(ValueLocation::Stack(loc), &value).into();
            let flattened_value_len = flattened_value.0.len();
            Self::emit_stack_ops(flattened_value, RW::READ, rw_operations);

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
                    Ok((ContainerValue::pack(fields?), flattened_value_len))
                }
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as struct", v))),
            }
        }
    }

    pub fn pop_as_reference(
        &mut self,
        rw_operations: &mut Vec<RWOperation>,
    ) -> VmResult<Reference> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();

            let flattened_value: LocatedFlattenedValue = LocatedValue(
                ValueLocation::Stack(StackLocation {
                    stack_index: self.0.len(),
                }),
                &value,
            )
            .into();
            Self::emit_stack_ops(flattened_value, RW::READ, rw_operations);

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
        rw_operations: &mut Vec<RWOperation>,
    ) -> VmResult<VectorRef> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();

            let flattened_value: LocatedFlattenedValue = LocatedValue(
                ValueLocation::Stack(StackLocation {
                    stack_index: self.0.len(),
                }),
                &value,
            )
            .into();
            Self::emit_stack_ops(flattened_value, RW::READ, rw_operations);

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
        rw_operations: &mut Vec<RWOperation>,
    ) -> VmResult<AccountAddress> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();
            let v_loc = StackLocation {
                stack_index: self.0.len(),
            };
            let flattened_value: LocatedFlattenedValue =
                LocatedValue(ValueLocation::Stack(v_loc), &value).into();
            Self::emit_stack_ops(flattened_value, RW::READ, rw_operations);

            match value {
                Value::Address(addr) => Ok(addr),
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as account address", v))),
            }
        }
    }

    pub fn pop_as_u64(&mut self, rw_operations: &mut Vec<RWOperation>) -> VmResult<u64> {
        if self.0.is_empty() {
            Err(RuntimeError::new(StatusCode::StackUnderflow))
        } else {
            let value = self.0.pop().unwrap();
            let v_loc = StackLocation {
                stack_index: self.0.len(),
            };
            let flattened_value: LocatedFlattenedValue =
                LocatedValue(ValueLocation::Stack(v_loc), &value).into();
            Self::emit_stack_ops(flattened_value, RW::READ, rw_operations);

            match value {
                Value::U64(v) => Ok(v.0 as u64),
                v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message(format!("cannot pop {:?} as U64", v))),
            }
        }
    }

    pub fn top(&self) -> Option<&Value> {
        self.0.last()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl Default for EvalStack {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CallStack(Vec<Frame>);

impl CallStack {
    pub fn new() -> Self {
        CallStack(vec![])
    }

    pub fn push(&mut self, frame: Frame) -> VmResult<()> {
        if self.0.len() < CALL_STACK_SIZE {
            self.0.push(frame);
            Ok(())
        } else {
            Err(RuntimeError::new(StatusCode::StackOverflow))
        }
    }

    pub fn pop(&mut self) -> Option<Frame> {
        if self.0.is_empty() {
            None
        } else {
            Some(self.0.pop().unwrap())
        }
    }

    pub fn top(&mut self) -> Option<&mut Frame> {
        self.0.last_mut()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl Default for CallStack {
    fn default() -> Self {
        Self::new()
    }
}
