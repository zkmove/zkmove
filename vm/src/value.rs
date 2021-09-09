use bellman::pairing::Engine;
use bellman::{ConstraintSystem, LinearCombination, Variable};
use error::{RuntimeError, StatusCode, VmResult};
use ff::{Field, PrimeField, PrimeFieldRepr};
use movelang::argument::ScriptArgument;
use movelang::value::MoveValue::{Bool, U128, U64, U8};
use movelang::value::{MoveValue, MoveValueType};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use std::convert::{TryFrom, TryInto};

#[derive(Clone)]
pub struct FFConstant<E: Engine> {
    pub value: E::Fr,
    pub ty: MoveValueType,
}

#[derive(Clone)]
pub struct FFVariable<E: Engine> {
    pub value: Option<E::Fr>,
    pub variable: Variable,
    pub ty: MoveValueType,
}

#[derive(Clone)]
pub enum Value<E: Engine> {
    Invalid,
    Constant(FFConstant<E>),
    Variable(FFVariable<E>),
}

impl<E: Engine> Value<E> {
    pub fn new_variable(
        value: Option<E::Fr>,
        variable: Variable,
        ty: MoveValueType,
    ) -> VmResult<Self> {
        Ok(Self::Variable(FFVariable {
            value,
            variable,
            ty,
        }))
    }
    pub fn bool(x: bool) -> VmResult<Self> {
        let value = if x { E::Fr::one() } else { E::Fr::zero() };
        Ok(Self::Constant(FFConstant {
            value,
            ty: MoveValueType::Bool,
        }))
    }
    pub fn u8(x: u8) -> VmResult<Self> {
        let value = biguint_to_fr::<E>(x.into())
            .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
        Ok(Self::Constant(FFConstant {
            value,
            ty: MoveValueType::U8,
        }))
    }
    pub fn u64(x: u64) -> VmResult<Self> {
        let value = biguint_to_fr::<E>(x.into())
            .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
        Ok(Self::Constant(FFConstant {
            value,
            ty: MoveValueType::U64,
        }))
    }
    pub fn u128(x: u128) -> VmResult<Self> {
        let value = biguint_to_fr::<E>(x.into())
            .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
        Ok(Self::Constant(FFConstant {
            value,
            ty: MoveValueType::U128,
        }))
    }
    pub fn value(&self) -> Option<E::Fr> {
        match self {
            Self::Invalid => None,
            Self::Constant(c) => Some(c.value),
            Self::Variable(v) => v.value,
        }
    }
    pub fn lc<CS: ConstraintSystem<E>>(&self) -> LinearCombination<E> {
        match self {
            Self::Invalid => {
                unreachable!()
            }
            Self::Constant(c) => LinearCombination::zero() + (c.value, CS::one()),
            Self::Variable(v) => LinearCombination::zero() + v.variable,
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

pub fn biguint_to_fr<E: Engine>(biguint: BigUint) -> Option<E::Fr> {
    E::Fr::from_str(&biguint.to_str_radix(10))
}

pub fn fr_to_biguint<Fr: PrimeField>(fr: &Fr) -> BigUint {
    let mut bytes = Vec::<u8>::new();
    fr.into_repr()
        .write_be(&mut bytes)
        .expect("failed to get Fr bytes");
    BigUint::from_bytes_be(&bytes)
}

impl<E: Engine> TryFrom<ScriptArgument> for Value<E> {
    type Error = RuntimeError;

    fn try_from(arg: ScriptArgument) -> VmResult<Value<E>> {
        match arg {
            ScriptArgument::U8(i) => Value::u8(i),
            ScriptArgument::U64(i) => Value::u64(i),
            ScriptArgument::U128(i) => Value::u128(i),
            ScriptArgument::Bool(b) => Value::bool(b),
            _ => Err(RuntimeError::new(StatusCode::UnsupportedMoveType)),
        }
    }
}

impl<E: Engine> TryFrom<Option<ScriptArgument>> for Value<E> {
    type Error = RuntimeError;

    fn try_from(arg: Option<ScriptArgument>) -> VmResult<Value<E>> {
        match arg {
            Some(ScriptArgument::U8(i)) => Value::u8(i),
            Some(ScriptArgument::U64(i)) => Value::u64(i),
            Some(ScriptArgument::U128(i)) => Value::u128(i),
            Some(ScriptArgument::Bool(b)) => Value::bool(b),
            _ => Err(RuntimeError::new(StatusCode::ValueConversionError)),
        }
    }
}

impl<E: Engine> TryInto<Option<MoveValue>> for Value<E> {
    type Error = RuntimeError;

    fn try_into(self) -> VmResult<Option<MoveValue>> {
        match self.value() {
            Some(fr) => {
                let big = fr_to_biguint(&fr);
                let value = match self.ty() {
                    MoveValueType::U8 => U8(big
                        .to_u8()
                        .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?),
                    MoveValueType::U64 => U64(big
                        .to_u64()
                        .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?),
                    MoveValueType::U128 => U128(
                        big.to_u128()
                            .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?,
                    ),
                    MoveValueType::Bool => Bool(!fr.is_zero()),
                    _ => unimplemented!(),
                };
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

impl<E: Engine> TryFrom<MoveValue> for Value<E> {
    type Error = RuntimeError;

    fn try_from(value: MoveValue) -> VmResult<Value<E>> {
        match value {
            U8(u) => Value::u8(u),
            U64(u) => Value::u64(u),
            U128(u) => Value::u128(u),
            Bool(b) => Value::bool(b),
            _ => unimplemented!(),
        }
    }
}
