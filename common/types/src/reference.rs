// Copyright (c) zkMove Authors

use crate::value::Value;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use movelang::value::MoveValueType;
use std::{borrow::Borrow, cell::RefCell, rc::Rc};

#[derive(Clone, Debug)]
pub struct MutRef<F: FieldExt> {
    pub index: usize,
    pub container: Rc<RefCell<Vec<Value<F>>>>,
    pub ty: MoveValueType,
}

#[derive(Clone, Debug)]
pub struct ImmRef<F: FieldExt> {
    pub index: usize,
    pub container: Rc<RefCell<Vec<Value<F>>>>,
    pub ty: MoveValueType,
}

#[derive(Clone, Debug)]
pub enum Ref<F: FieldExt> {
    Mut(MutRef<F>),
    Imm(ImmRef<F>),
}

impl<F: FieldExt> Ref<F> {
    pub fn new_mut(index: usize, container: Rc<RefCell<Vec<Value<F>>>>, ty: MoveValueType) -> Self {
        Self::Mut(MutRef {
            index,
            container,
            ty,
        })
    }

    pub fn new_imm(index: usize, container: Rc<RefCell<Vec<Value<F>>>>, ty: MoveValueType) -> Self {
        Self::Imm(ImmRef {
            index,
            container,
            ty,
        })
    }

    pub fn read(&self) -> VmResult<Value<F>> {
        match self {
            Self::Mut(r) => {
                let values: &RefCell<Vec<Value<F>>> = r.container.borrow();
                match values.borrow().get(r.index) {
                    Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::BorrowLocalError)),
                    Some(v) => Ok(v.clone()),
                    None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
                }
            }
            Self::Imm(r) => {
                let values: &RefCell<Vec<Value<F>>> = r.container.borrow();
                match values.borrow().get(r.index) {
                    Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::BorrowLocalError)),
                    Some(v) => Ok(v.clone()),
                    None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
                }
            }
        }
    }

    pub fn write(&mut self, value: Value<F>) -> VmResult<()> {
        match self {
            Self::Mut(r) => {
                let values: &RefCell<Vec<Value<F>>> = r.container.borrow();
                match values.borrow_mut().get_mut(r.index) {
                    Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::BorrowLocalError)),
                    Some(v) => {
                        *v = value;
                        Ok(())
                    }
                    None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
                }
            }
            Self::Imm(_r) => Err(RuntimeError::new(StatusCode::BorrowLocalError)),
        }
    }

    pub fn ty(&self) -> MoveValueType {
        match self {
            Self::Mut(r) => r.ty.clone(),
            Self::Imm(r) => r.ty.clone(),
        }
    }

    pub fn equals(&self, other: &Self) -> VmResult<bool> {
        if self.ty() != other.ty() {
            return Ok(false);
        }

        Ok(self.read()? == other.read()?)
    }
}
