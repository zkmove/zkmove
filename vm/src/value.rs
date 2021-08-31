use crate::error::{RuntimeError, StatusCode, VmResult};
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, LinearCombination, Variable};
use ff::{Field, PrimeField, PrimeFieldRepr};
use movelang::argument::ScriptArgument;
use num_bigint::BigUint;
use std::convert::TryFrom;

#[derive(Clone)]
pub struct FFConstant<E: Engine> {
    pub value: E::Fr,
}

#[derive(Clone)]
pub struct FFVariable<E: Engine> {
    pub value: Option<E::Fr>,
    pub variable: Variable,
}

#[derive(Clone)]
pub enum Value<E: Engine> {
    Invalid,
    Constant(FFConstant<E>),
    Variable(FFVariable<E>),
}

impl<E: Engine> Value<E> {
    pub fn new_variable(value: Option<E::Fr>, variable: Variable) -> VmResult<Self> {
        Ok(Self::Variable(FFVariable { value, variable }))
    }
    pub fn bool(x: bool) -> VmResult<Self> {
        let value = if x { E::Fr::one() } else { E::Fr::zero() };
        Ok(Self::Constant(FFConstant { value }))
    }
    pub fn u8(x: u8) -> VmResult<Self> {
        let value = biguint_to_fr::<E>(x.into())
            .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
        Ok(Self::Constant(FFConstant { value }))
    }
    pub fn u64(x: u64) -> VmResult<Self> {
        let value = biguint_to_fr::<E>(x.into())
            .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
        Ok(Self::Constant(FFConstant { value }))
    }
    pub fn u128(x: u128) -> VmResult<Self> {
        let value = biguint_to_fr::<E>(x.into())
            .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
        Ok(Self::Constant(FFConstant { value }))
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
