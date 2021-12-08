// Copyright (c) zkMove Authors

use error::VmResult;
use halo2::{arithmetic::FieldExt, circuit::Cell};
use movelang::value::MoveValue::{Bool, U128, U64, U8};
use movelang::value::{MoveValue, MoveValueType};

#[derive(Clone)]
pub struct FConstant<F: FieldExt> {
    pub value: F,
    pub cell: Option<Cell>,
    pub ty: MoveValueType,
}

impl<F: FieldExt> FConstant<F> {
    fn equals(&self, other: &Self) -> bool {
        if self.ty != other.ty {
            return false;
        }
        if self.value == other.value {
            match (self.cell, other.cell) {
                (Some(c1), Some(c2)) => c1 == c2,
                (None, None) => true,
                _ => false,
            }
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub struct FVariable<F: FieldExt> {
    pub value: Option<F>,
    pub cell: Option<Cell>,
    pub ty: MoveValueType,
}

impl<F: FieldExt> FVariable<F> {
    fn equals(&self, other: &Self) -> bool {
        if self.ty != other.ty {
            return false;
        }
        let eq_value = match (self.value, other.value) {
            (Some(v1), Some(v2)) => v1 == v2,
            (None, None) => true,
            _ => false,
        };
        let eq_cell = match (self.cell, other.cell) {
            (Some(c1), Some(c2)) => c1 == c2,
            (None, None) => true,
            _ => false,
        };
        eq_value && eq_cell
    }
}

#[derive(Clone)]
pub enum Value<F: FieldExt> {
    Invalid,
    Constant(FConstant<F>),
    Variable(FVariable<F>),
}

impl<F: FieldExt> Value<F> {
    pub fn new_variable(value: Option<F>, cell: Option<Cell>, ty: MoveValueType) -> VmResult<Self> {
        Ok(Self::Variable(FVariable { value, cell, ty }))
    }
    pub fn new_constant(value: F, cell: Option<Cell>, ty: MoveValueType) -> VmResult<Self> {
        Ok(Self::Constant(FConstant { value, cell, ty }))
    }
    pub fn bool(x: bool, cell: Option<Cell>) -> VmResult<Self> {
        let value = if x { F::one() } else { F::zero() };
        Ok(Self::Constant(FConstant {
            value,
            cell,
            ty: MoveValueType::Bool,
        }))
    }
    pub fn u8(x: u8, cell: Option<Cell>) -> VmResult<Self> {
        let value = F::from_u64(x as u64); //todo: range check
        Ok(Self::Constant(FConstant {
            value,
            cell,
            ty: MoveValueType::U8,
        }))
    }
    pub fn u64(x: u64, cell: Option<Cell>) -> VmResult<Self> {
        let value = F::from_u64(x);
        Ok(Self::Constant(FConstant {
            value,
            cell,
            ty: MoveValueType::U64,
        }))
    }
    pub fn u128(x: u128, cell: Option<Cell>) -> VmResult<Self> {
        let value = F::from_u128(x);
        Ok(Self::Constant(FConstant {
            value,
            cell,
            ty: MoveValueType::U128,
        }))
    }
    pub fn value(&self) -> Option<F> {
        match self {
            Self::Invalid => None,
            Self::Constant(c) => Some(c.value),
            Self::Variable(v) => v.value,
        }
    }
    pub fn cell(&self) -> Option<Cell> {
        match self {
            Self::Invalid => None,
            Self::Constant(c) => c.cell,
            Self::Variable(v) => v.cell,
        }
    }
    pub fn ty(&self) -> MoveValueType {
        match self {
            Self::Invalid => {
                unreachable!()
            }
            Self::Constant(c) => c.ty.clone(),
            Self::Variable(v) => v.ty.clone(),
        }
    }

    pub fn equals(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Invalid, Self::Invalid) => true,
            (Self::Constant(c1), Self::Constant(c2)) => c1.equals(c2),
            (Self::Variable(v1), Self::Variable(v2)) => v1.equals(v2),
            _ => false,
        }
    }
}

impl<F: FieldExt> Into<Option<MoveValue>> for Value<F> {
    fn into(self) -> Option<MoveValue> {
        match self.value() {
            Some(field) => {
                let value = match self.ty() {
                    MoveValueType::U8 => U8(field.get_lower_128() as u8),
                    MoveValueType::U64 => U64(field.get_lower_128() as u64),
                    MoveValueType::U128 => U128(field.get_lower_128()),
                    MoveValueType::Bool => Bool(field == F::one()),
                    _ => unimplemented!(),
                };
                Some(value)
            }
            None => None,
        }
    }
}
