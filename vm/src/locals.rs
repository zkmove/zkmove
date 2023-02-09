// Copyright (c) zkMove Authors

use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use movelang::value::{
    AddressPath, Container, ContainerRef, FrameIndex, Index, IndexedRef, Value, ValueAddress,
};
use std::{cell::RefCell, rc::Rc};
use vm_circuit::witness::rw_operations::{LocalsOp, RWOperation, RW};

#[derive(Clone)]
pub struct Locals<F: FieldExt>(Rc<RefCell<Vec<Value<F>>>>);

impl<F: FieldExt> Locals<F> {
    pub fn new(size: usize) -> Self {
        Self(Rc::new(RefCell::new(vec![Value::Invalid; size])))
    }

    pub fn emit_locals_ops_for_flattened_value(
        flattened: Vec<(AddressPath, Value<F>)>,
        rw: RW,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) {
        for (address_path, val) in flattened {
            let locals_op = LocalsOp {
                frame_index: *address_path
                    .0
                    .get(0)
                    .expect("frame_index should not be None"),
                index: *address_path.0.get(1).expect("index should not be None"),
                nested_address_0: *address_path
                    .0
                    .get(2)
                    .expect("nested_address_0 should not be None"),
                nested_address_1: *address_path
                    .0
                    .get(3)
                    .expect("nested_address_1 should not be None"),
                value: val,
                rw: rw.clone(),
                gc: rw_operations.len(),
            };
            rw_operations.push(RWOperation::LocalsOp(locals_op));
        }
    }
    pub fn copy(
        &self,
        index: usize,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::CopyLocalError)),
            Some(v) => {
                let flattened =
                    v.flatten(ValueAddress::Locals(FrameIndex(frame_index), Index(index)))?;
                Self::emit_locals_ops_for_flattened_value(flattened, RW::READ, rw_operations);
                Ok(v.copy_value())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn store(
        &self,
        index: usize,
        value: Value<F>,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<()> {
        let value = Value::update_address(
            value,
            ValueAddress::Locals(FrameIndex(frame_index), Index(index)),
        );
        let flattened =
            value.flatten(ValueAddress::Locals(FrameIndex(frame_index), Index(index)))?;

        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            Some(v) => {
                if let Value::Container(c) = v {
                    if c.rc_count() > 1 {
                        return Err(
                            RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                                .with_message(
                                    "moving container with dangling references".to_string(),
                                ),
                        );
                    }
                }

                Self::emit_locals_ops_for_flattened_value(flattened, RW::WRITE, rw_operations);

                values[index] = value;
                Ok(())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn move_(
        &self,
        index: usize,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let value_copy = self.0.borrow().get(index).cloned().unwrap();
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::MoveLocalError)),
            Some(v) => {
                let flattened = value_copy
                    .flatten(ValueAddress::Locals(FrameIndex(frame_index), Index(index)))?;
                Self::emit_locals_ops_for_flattened_value(flattened, RW::READ, rw_operations);
                let locals_op_2 = LocalsOp {
                    frame_index,
                    index,
                    nested_address_0: 0,
                    nested_address_1: 0,
                    value: Value::Invalid,
                    rw: RW::WRITE,
                    gc: rw_operations.len(),
                };
                rw_operations.push(RWOperation::LocalsOp(locals_op_2));
                Ok(std::mem::replace(v, Value::Invalid))
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn mut_borrow(
        &self,
        index: usize,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::MutBorrowLocalError)),
            Some(v) => match v {
                Value::U8(_) | Value::U64(_) | Value::U128(_) | Value::Bool(_) => {
                    let flattened =
                        v.flatten(ValueAddress::Locals(FrameIndex(frame_index), Index(index)))?;
                    Self::emit_locals_ops_for_flattened_value(flattened, RW::READ, rw_operations);
                    Ok(Value::IndexedRef(IndexedRef {
                        index,
                        container_ref: ContainerRef::Local(Container::Locals(
                            FrameIndex(frame_index),
                            Rc::clone(&self.0),
                        )),
                    }))
                }
                Value::Container(c) => {
                    let flattened =
                        v.flatten(ValueAddress::Locals(FrameIndex(frame_index), Index(index)))?;
                    Self::emit_locals_ops_for_flattened_value(flattened, RW::READ, rw_operations);
                    Ok(Value::ContainerRef(ContainerRef::Local(c.copy_by_ref())))
                }
                _ => unimplemented!(),
            },
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn imm_borrow(
        &self,
        index: usize,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::ImmBorrowLocalError)),
            Some(v) => match v {
                Value::U8(_) | Value::U64(_) | Value::U128(_) | Value::Bool(_) => {
                    let flattened =
                        v.flatten(ValueAddress::Locals(FrameIndex(frame_index), Index(index)))?;
                    Self::emit_locals_ops_for_flattened_value(flattened, RW::READ, rw_operations);
                    Ok(Value::IndexedRef(IndexedRef {
                        index,
                        container_ref: ContainerRef::Local(Container::Locals(
                            FrameIndex(frame_index),
                            Rc::clone(&self.0),
                        )),
                    }))
                }
                Value::Container(c) => {
                    let flattened =
                        v.flatten(ValueAddress::Locals(FrameIndex(frame_index), Index(index)))?;
                    Self::emit_locals_ops_for_flattened_value(flattened, RW::READ, rw_operations);
                    Ok(Value::ContainerRef(ContainerRef::Local(c.copy_by_ref())))
                }
                _ => unimplemented!(),
            },
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn read_ref(
        &self,
        index: usize,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::ImmBorrowLocalError)),
            Some(v) => {
                let flattened =
                    v.flatten(ValueAddress::Locals(FrameIndex(frame_index), Index(index)))?;
                Self::emit_locals_ops_for_flattened_value(flattened, RW::READ, rw_operations);
                Ok(v.clone())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn write_ref(
        &self,
        index: usize,
        value: Value<F>,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<()> {
        let flattened =
            value.flatten(ValueAddress::Locals(FrameIndex(frame_index), Index(index)))?;
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::ImmBorrowLocalError)),
            Some(_v) => {
                Self::emit_locals_ops_for_flattened_value(flattened, RW::WRITE, rw_operations);
                values[index] = value;
                Ok(())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn flattened_field_count(&self, index: usize) -> VmResult<usize> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::ImmBorrowLocalError)),
            Some(v) => v.flattened_field_count(),
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }
}

impl<F: FieldExt> Locals<F> {
    pub fn len(&self) -> usize {
        self.0.borrow().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.borrow().is_empty()
    }
}
