// Copyright (c) zkMove Authors

use crate::value::Value;
use error::{RuntimeError, StatusCode, VmResult};
use halo2::arithmetic::FieldExt;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone)]
pub struct Locals<F: FieldExt>(Rc<RefCell<Vec<Value<F>>>>);

impl<F: FieldExt> Locals<F> {
    pub fn new(size: usize) -> Self {
        Self(Rc::new(RefCell::new(vec![Value::Invalid; size])))
    }

    pub fn copy(&self, index: usize) -> VmResult<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::CopyLocalError)),
            Some(v) => Ok(v.clone()),
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn store(&mut self, index: usize, value: Value<F>) -> VmResult<()> {
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            // Todo: check ref count
            Some(_v) => {
                values[index] = value;
                Ok(())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn move_(&self, index: usize) -> VmResult<Value<F>> {
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::MoveLocalError)),
            Some(v) => Ok(std::mem::replace(v, Value::Invalid)),
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }
}

impl<F: FieldExt> Locals<F> {
    pub fn len(&self) -> usize {
        self.0.borrow().len()
    }

    pub fn get(&self, index: usize) -> Option<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Some(Value::Invalid),
            Some(v) => Some(v.clone()),
            None => None,
        }
    }
}
