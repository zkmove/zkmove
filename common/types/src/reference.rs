// Copyright (c) zkMove Authors

use crate::value::Value;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use movelang::value::MoveValueType;
use std::{borrow::Borrow, cell::RefCell, rc::Rc};

#[derive(Clone, Debug)]
pub struct MutRef {
    pub index: usize,
    pub ty: MoveValueType,
}

#[derive(Clone, Debug)]
pub struct ImmRef {
    pub index: usize,
    pub ty: MoveValueType,
}

#[derive(Clone, Debug)]
pub enum Ref {
    Mut(MutRef),
    Imm(ImmRef),
}

impl Ref {
    pub fn new_mut(index: usize, ty: MoveValueType) -> Self {
        Self::Mut(MutRef { index, ty })
    }

    pub fn new_imm(index: usize, ty: MoveValueType) -> Self {
        Self::Imm(ImmRef { index, ty })
    }

    pub fn ty(&self) -> MoveValueType {
        match self {
            Self::Mut(r) => r.ty.clone(),
            Self::Imm(r) => r.ty.clone(),
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Ref::Mut(r) => r.index,
            Ref::Imm(r) => r.index,
        }
    }

    pub fn equals(&self, other: &Self) -> VmResult<bool> {
        if self.ty() != other.ty() {
            return Ok(false);
        }

        Ok(self.index() == other.index())
    }

    pub fn is_mut(&self) -> bool {
        match self {
            Self::Mut(_) => true,
            Self::Imm(_) => false,
        }
    }

    pub fn freeze(&self) -> Self {
        match self {
            Self::Mut(r) => Self::Imm(ImmRef {
                index: r.index,
                ty: r.ty.clone(),
            }),
            Self::Imm(_) => self.clone(),
        }
    }
}
