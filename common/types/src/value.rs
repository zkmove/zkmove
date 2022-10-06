// Copyright (c) zkMove Authors

use crate::reference::Ref;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::{arithmetic::FieldExt, circuit::Cell};
use movelang::value::MoveValue::{Bool, U128, U64, U8};
use movelang::value::{convert_to_field, move_div, move_rem};
use movelang::value::{MoveValue, MoveValueType};
use std::ops::{Add, Div, Mul, Not, Rem, Sub};

pub const NUM_OF_BYTES_U128: usize = 16;

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub enum Value<F: FieldExt> {
    Invalid,
    Constant(FConstant<F>),
    Variable(FVariable<F>),
    Reference(Ref<F>),
}

impl<F: FieldExt> Value<F> {
    pub fn new_variable(value: Option<F>, cell: Option<Cell>, ty: MoveValueType) -> VmResult<Self> {
        Ok(Self::Variable(FVariable { value, cell, ty }))
    }
    pub fn new_constant(value: F, cell: Option<Cell>, ty: MoveValueType) -> VmResult<Self> {
        Ok(Self::Constant(FConstant { value, cell, ty }))
    }
    pub fn new_reference(reference: Ref<F>) -> VmResult<Self> {
        Ok(Self::Reference(reference))
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
        let value = F::from_u128(x as u128); //todo: range check
        Ok(Self::Constant(FConstant {
            value,
            cell,
            ty: MoveValueType::U8,
        }))
    }
    pub fn u64(x: u64, cell: Option<Cell>) -> VmResult<Self> {
        let value = F::from_u128(x as u128);
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
    pub fn value(&self) -> VmResult<Option<F>> {
        match self {
            Self::Invalid => Ok(None),
            Self::Constant(c) => Ok(Some(c.value)),
            Self::Variable(v) => Ok(v.value),
            Self::Reference(r) => r.read()?.value(),
        }
    }
    pub fn cell(&self) -> Option<Cell> {
        match self {
            Self::Invalid => None,
            Self::Constant(c) => c.cell,
            Self::Variable(v) => v.cell,
            Self::Reference(_r) => None,
        }
    }
    pub fn ty(&self) -> MoveValueType {
        match self {
            Self::Invalid => {
                unreachable!()
            }
            Self::Constant(c) => c.ty.clone(),
            Self::Variable(v) => v.ty.clone(),
            Self::Reference(r) => r.ty(),
        }
    }

    pub fn equals(&self, other: &Self) -> VmResult<bool> {
        match (self, other) {
            (Self::Invalid, Self::Invalid) => Ok(true),
            (Self::Constant(c1), Self::Constant(c2)) => Ok(c1.equals(c2)),
            (Self::Variable(v1), Self::Variable(v2)) => Ok(v1.equals(v2)),
            (Self::Reference(r1), Self::Reference(r2)) => r1.equals(r2),
            _ => Ok(false),
        }
    }

    pub fn less_than(&self, other: &Self) -> VmResult<bool> {
        match (self.value()?, other.value()?) {
            (Some(v1), Some(v2)) => Ok(v1 < v2),
            _ => Err(RuntimeError::new(StatusCode::InternalError)),
        }
    }

    pub fn is_zero(&self) -> VmResult<bool> {
        match self.value()? {
            Some(v) => Ok(v.is_zero_vartime()),
            None => Ok(false),
        }
    }

    pub fn div_rem(&self, other: Value<F>) -> VmResult<(Value<F>, Value<F>)> {
        let l_move: Option<MoveValue> = self.clone().into();
        let r_move: Option<MoveValue> = other.into();
        match (l_move, r_move) {
            (Some(l), Some(r)) => {
                let quo = move_div(l.clone(), r.clone())?;
                let rem = move_rem(l, r)?;
                let quo_field = Some(convert_to_field::<F>(quo));
                let rem_field = Some(convert_to_field::<F>(rem));
                let quo_value = Value::new_variable(quo_field, None, self.ty())?;
                let rem_value = Value::new_variable(rem_field, None, self.ty())?;
                Ok((quo_value, rem_value))
            }
            _ => Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("Move value should not be None".to_string())),
        }
    }
}

impl<F: FieldExt> PartialEq for Value<F> {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other).unwrap_or(false)
    }
}

impl<F: FieldExt> Eq for Value<F> {}

impl<F: FieldExt> Add for Value<F> {
    type Output = VmResult<Self>;

    fn add(self, b: Value<F>) -> Self::Output {
        let value = self.value()?.and_then(|a| b.value().ok()?.map(|b| a + b));
        let c = Value::new_variable(value, None, self.ty())?; //todo: refactor Value
        Ok(c)
    }
}

impl<F: FieldExt> Sub for Value<F> {
    type Output = VmResult<Self>;

    fn sub(self, b: Value<F>) -> Self::Output {
        let value = self.value()?.and_then(|a| b.value().ok()?.map(|b| a - b));
        let c = Value::new_variable(value, None, self.ty())?;
        Ok(c)
    }
}

impl<F: FieldExt> Mul for Value<F> {
    type Output = VmResult<Self>;

    fn mul(self, b: Value<F>) -> Self::Output {
        let value = self.value()?.and_then(|a| b.value().ok()?.map(|b| a * b));
        let c = Value::new_variable(value, None, self.ty())?;
        Ok(c)
    }
}

impl<F: FieldExt> Div for Value<F> {
    type Output = VmResult<Self>;

    fn div(self, b: Value<F>) -> Self::Output {
        let l_move: Option<MoveValue> = self.clone().into();
        let r_move: Option<MoveValue> = b.into();
        match (l_move, r_move) {
            (Some(l), Some(r)) => {
                let quo = move_div(l, r)?;
                let v = Some(convert_to_field::<F>(quo));
                let value = Value::new_variable(v, None, self.ty())?;
                Ok(value)
            }
            _ => Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("Move value should not be None".to_string())),
        }
    }
}

impl<F: FieldExt> Rem for Value<F> {
    type Output = VmResult<Self>;

    fn rem(self, b: Value<F>) -> Self::Output {
        let l_move: Option<MoveValue> = self.clone().into();
        let r_move: Option<MoveValue> = b.into();
        match (l_move, r_move) {
            (Some(l), Some(r)) => {
                let rem = move_rem(l, r)?;
                let v = Some(convert_to_field::<F>(rem));
                let value = Value::new_variable(v, None, self.ty())?;
                Ok(value)
            }
            _ => Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("Move value should not be None".to_string())),
        }
    }
}

impl<F: FieldExt> Not for Value<F> {
    type Output = VmResult<Self>;

    fn not(self) -> Self::Output {
        let value = if self.is_zero()? { F::one() } else { F::zero() };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }
}

impl<F: FieldExt> Value<F> {
    pub fn eq(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = match (a.value()?, b.value()?) {
            (Some(a), Some(b)) => {
                let fr = if a == b { F::one() } else { F::zero() };
                Some(fr)
            }
            _ => None,
        };

        let c = Value::new_variable(value, None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn neq(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if !a.equals(&b)? { F::one() } else { F::zero() };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn lt(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let lt = a.less_than(&b)?;
        let value = if lt { F::one() } else { F::zero() };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn and(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if a.is_zero()? || b.is_zero()? {
            F::zero()
        } else {
            F::one()
        };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn or(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if a.is_zero()? && b.is_zero()? {
            F::zero()
        } else {
            F::one()
        };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn delta_invert(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let delta_invert = if a.value().unwrap().unwrap() == b.value().unwrap().unwrap() {
            F::one()
        } else {
            let delta = a.value().unwrap().unwrap() - b.value().unwrap().unwrap();
            delta.invert().unwrap()
        };

        let value = Value::new_variable(Some(delta_invert), None, a.ty())?;
        Ok(value)
    }

    pub fn diff(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let lhs = a.value().unwrap().unwrap();
        let rhs = b.value().unwrap().unwrap();
        let range = F::from(2).pow(&[(NUM_OF_BYTES_U128 * 8) as u64, 0, 0, 0]);
        let range_or_zero = if lhs < rhs { range } else { F::zero() };
        let diff = (lhs - rhs) + range_or_zero;
        let value = Value::new_variable(Some(diff), None, a.ty())?;
        Ok(value)
    }
}

impl<F: FieldExt> From<Value<F>> for Option<MoveValue> {
    fn from(value: Value<F>) -> Option<MoveValue> {
        match value.value().unwrap() {
            Some(field) => {
                let value = match value.ty() {
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
