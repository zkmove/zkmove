// Copyright (c) zkMove Authors

use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use movelang::value::{Container, ContainerRef, IndexedRef};
use movelang::value::{IndexedLocalsRef, Value};
use std::{cell::RefCell, rc::Rc};
use vm_circuit::witness::rw_operations::{LocalsOp, RWOperation, RW};

#[derive(Clone)]
pub struct Locals<F: FieldExt>(Rc<RefCell<Vec<Value<F>>>>);

impl<F: FieldExt> Locals<F> {
    pub fn new(size: usize) -> Self {
        Self(Rc::new(RefCell::new(vec![Value::Invalid; size])))
    }

    pub fn copy(
        &self,
        index: usize,
        call_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::CopyLocalError)),
            Some(v) => {
                let locals_op = LocalsOp {
                    call_index,
                    index,
                    value: v.clone(),
                    rw: RW::READ,
                    gc: rw_operations.len(),
                };
                rw_operations.push(RWOperation::LocalsOp(locals_op));
                Ok(v.copy_value())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn store(
        &self,
        index: usize,
        value: Value<F>,
        call_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<()> {
        let value_copy = value.clone();
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
                let locals_op = LocalsOp {
                    call_index,
                    index,
                    value: value_copy,
                    rw: RW::WRITE,
                    gc: rw_operations.len(),
                };
                rw_operations.push(RWOperation::LocalsOp(locals_op));
                values[index] = value;
                Ok(())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn move_(
        &self,
        index: usize,
        call_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let value_copy = self.0.borrow().get(index).cloned();
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::MoveLocalError)),
            Some(v) => {
                let locals_op_1 = LocalsOp {
                    call_index,
                    index,
                    value: value_copy.unwrap(),
                    rw: RW::READ,
                    gc: rw_operations.len(),
                };
                rw_operations.push(RWOperation::LocalsOp(locals_op_1));
                let locals_op_2 = LocalsOp {
                    call_index,
                    index,
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
        call_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::MutBorrowLocalError)),
            Some(v) => match v {
                Value::U8(_) | Value::U64(_) | Value::U128(_) | Value::Bool(_) => {
                    let locals_op = LocalsOp {
                        call_index,
                        index,
                        value: v.clone(),
                        rw: RW::READ,
                        gc: rw_operations.len(),
                    };
                    rw_operations.push(RWOperation::LocalsOp(locals_op));
                    Ok(Value::IndexedRef(IndexedRef::IndexedLocalsRef(
                        IndexedLocalsRef {
                            call_index,
                            idx: index,
                            container_ref: ContainerRef::Local(Container::Locals(Rc::clone(
                                &self.0,
                            ))),
                        },
                    )))
                }
                Value::Container(c) => {
                    let locals_op = LocalsOp {
                        call_index,
                        index,
                        value: v.clone(),
                        rw: RW::READ,
                        gc: rw_operations.len(),
                    };
                    rw_operations.push(RWOperation::LocalsOp(locals_op));
                    Ok(Value::IndexedRef(IndexedRef::IndexedLocalsRef(
                        IndexedLocalsRef {
                            call_index,
                            idx: index,
                            container_ref: ContainerRef::Local(c.copy_by_ref()),
                        },
                    )))
                }
                _ => unimplemented!(),
            },
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn imm_borrow(
        &self,
        index: usize,
        call_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::ImmBorrowLocalError)),
            Some(v) => match v {
                Value::U8(_) | Value::U64(_) | Value::U128(_) | Value::Bool(_) => {
                    let locals_op = LocalsOp {
                        call_index,
                        index,
                        value: v.clone(),
                        rw: RW::READ,
                        gc: rw_operations.len(),
                    };
                    rw_operations.push(RWOperation::LocalsOp(locals_op));
                    Ok(Value::IndexedRef(IndexedRef::IndexedLocalsRef(
                        IndexedLocalsRef {
                            call_index,
                            idx: index,
                            container_ref: ContainerRef::Local(Container::Locals(Rc::clone(
                                &self.0,
                            ))),
                        },
                    )))
                }
                Value::Container(c) => {
                    let locals_op = LocalsOp {
                        call_index,
                        index,
                        value: v.clone(),
                        rw: RW::READ,
                        gc: rw_operations.len(),
                    };
                    rw_operations.push(RWOperation::LocalsOp(locals_op));
                    Ok(Value::IndexedRef(IndexedRef::IndexedLocalsRef(
                        IndexedLocalsRef {
                            call_index,
                            idx: index,
                            container_ref: ContainerRef::Local(c.copy_by_ref()),
                        },
                    )))
                }
                _ => unimplemented!(),
            },
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn read_ref(
        &self,
        index: usize,
        call_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::ImmBorrowLocalError)),
            Some(v) => {
                let locals_op = LocalsOp {
                    call_index,
                    index,
                    value: v.clone(),
                    rw: RW::READ,
                    gc: rw_operations.len(),
                };
                rw_operations.push(RWOperation::LocalsOp(locals_op));
                Ok(v.clone())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn write_ref(
        &self,
        index: usize,
        value: Value<F>,
        call_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<()> {
        let value_copy = value.clone();
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::ImmBorrowLocalError)),
            Some(_v) => {
                let locals_op = LocalsOp {
                    call_index,
                    index,
                    value: value_copy,
                    rw: RW::WRITE,
                    gc: rw_operations.len(),
                };
                rw_operations.push(RWOperation::LocalsOp(locals_op));
                values[index] = value;
                Ok(())
            }
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
