// Copyright (c) zkMove Authors

use crate::value::Value;
use crate::vm_circuit::circuit_inputs::rw_operations::{LocalsOp, RWOperation, RW};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use std::{cell::RefCell, rc::Rc};

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
                Ok(v.clone())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn store(
        &mut self,
        index: usize,
        value: Value<F>,
        call_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<()> {
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            // Todo: check ref count
            Some(_v) => {
                let locals_op = LocalsOp {
                    call_index,
                    index,
                    value: value.clone(),
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
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::MoveLocalError)),
            Some(v) => {
                let locals_op_1 = LocalsOp {
                    call_index,
                    index,
                    value: v.clone(),
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
}

impl<F: FieldExt> Locals<F> {
    pub fn len(&self) -> usize {
        self.0.borrow().len()
    }
}
