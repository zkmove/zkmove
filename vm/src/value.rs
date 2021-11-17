use bellman::pairing::Engine;
use bellman::{ConstraintSystem, LinearCombination, Variable};
use error::{RuntimeError, StatusCode, VmResult};
use ff::{Field, PrimeField, PrimeFieldRepr};
use halo2::{arithmetic::FieldExt, circuit::Cell};
use movelang::argument::ScriptArgument;
use movelang::value::MoveValue::{Bool, U128, U64, U8};
use movelang::value::{MoveValue, MoveValueType};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use std::convert::{TryFrom, TryInto};
#[derive(Clone)]
pub struct Alloc<F: FieldExt> {
    pub cell: Cell,
    pub value: Option<F>,
}

#[derive(Clone)]
pub struct FConstant<F: FieldExt> {
    pub value: F,
    pub cell: Cell,
    pub ty: MoveValueType,
}

#[derive(Clone)]
pub struct FVariable<F: FieldExt> {
    pub value: Option<F>,
    pub cell: Cell,
    pub ty: MoveValueType,
}

#[derive(Clone)]
pub enum Value<F: FieldExt> {
    Invalid,
    Constant(FConstant<F>),
    Variable(FVariable<F>),
}

impl<F: FieldExt> Value<F> {
    pub fn new_variable(
        value: Option<F>,
        cell: Cell,
        ty: MoveValueType,
    ) -> VmResult<Self> {
        Ok(Self::Variable(FVariable {
            value,
            cell,
            ty,
        }))
    }
    pub fn bool(x: bool, cell: Cell) -> VmResult<Self> {
        let value = if x { F::one() } else { F::zero() };
        Ok(Self::Constant(FConstant {
            value,
            cell,
            ty: MoveValueType::Bool,
        }))
    }
    pub fn u8(x: u8, cell: Cell) -> VmResult<Self> {
        let value = F::from_u64(x as u64);  //todo: range check
        Ok(Self::Constant(FConstant {
            value,
            cell,
            ty: MoveValueType::U8,
        }))
    }
    pub fn u64(x: u64, cell: Cell) -> VmResult<Self> {
        let value = F::from_u64(x);
        Ok(Self::Constant(FConstant {
            value,
            cell,
            ty: MoveValueType::U64,
        }))
    }
    pub fn u128(x: u128, cell: Cell) -> VmResult<Self> {
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
    pub fn ty(&self) -> MoveValueType {
        match self {
            Self::Invalid => {
                unreachable!()
            }
            Self::Constant(c) => c.ty.clone(),
            Self::Variable(v) => v.ty.clone(),
        }
    }
}

pub fn fr_to_biguint<Fr: PrimeField>(fr: &Fr) -> BigUint {
    let mut bytes = Vec::<u8>::new();
    fr.into_repr()
        .write_be(&mut bytes)
        .expect("failed to get Fr bytes");
    BigUint::from_bytes_be(&bytes)
}

impl<F: FieldExt> TryFrom<ScriptArgument> for Value<F> {
    type Error = RuntimeError;

    fn try_from(arg: ScriptArgument) -> VmResult<Value<F>> {
        match arg {
            // ScriptArgument::U8(i) => Value::u8(i),
            // ScriptArgument::U64(i) => Value::u64(i),
            // ScriptArgument::U128(i) => Value::u128(i),
            // ScriptArgument::Bool(b) => Value::bool(b),
            _ => Err(RuntimeError::new(StatusCode::UnsupportedMoveType)),
        }
    }
}

impl<F: FieldExt> TryInto<Option<MoveValue>> for Value<F> {
    type Error = RuntimeError;

    fn try_into(self) -> VmResult<Option<MoveValue>> {
        // match self.value() {
        //     Some(fr) => {
        //         let big = fr_to_biguint(&fr);
        //         let value = match self.ty() {
        //             MoveValueType::U8 => U8(big
        //                 .to_u8()
        //                 .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?),
        //             MoveValueType::U64 => U64(big
        //                 .to_u64()
        //                 .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?),
        //             MoveValueType::U128 => U128(
        //                 big.to_u128()
        //                     .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?,
        //             ),
        //             MoveValueType::Bool => Bool(!fr.is_zero()),
        //             _ => unimplemented!(),
        //         };
        //         Ok(Some(value))
        //     }
        //     None => Ok(None),
        // }
        Ok(None)  //workaround
    }
}

impl<F: FieldExt> TryFrom<MoveValue> for Value<F> {
    type Error = RuntimeError;

    fn try_from(value: MoveValue) -> VmResult<Value<F>> {
        match value {
            // U8(u) => Value::u8(u),
            // U64(u) => Value::u64(u),
            // U128(u) => Value::u128(u),
            // Bool(b) => Value::bool(b),
            _ => unimplemented!(),
        }
    }
}
