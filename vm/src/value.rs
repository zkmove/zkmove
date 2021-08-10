use crate::error::{RuntimeError, StatusCode, VmResult};
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, LinearCombination, Variable};
use ff::PrimeField;
use num_bigint::BigUint;

pub struct FFConstant<E: Engine> {
    pub value: E::Fr,
}

pub struct FFVariable<E: Engine> {
    pub value: Option<E::Fr>,
    pub variable: Variable,
}

pub enum Value<E: Engine> {
    Constant(FFConstant<E>),
    Variable(FFVariable<E>),
}

impl<E: Engine> Value<E> {
    pub fn new_variable(value: Option<E::Fr>, variable: Variable) -> VmResult<Self> {
        Ok(Self::Variable(FFVariable { value, variable }))
    }
    pub fn u8(x: u8) -> VmResult<Self> {
        let value = biguint_to_fr::<E>(x.into())
            .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
        Ok(Self::Constant(FFConstant { value }))
    }
    pub fn value(&self) -> Option<E::Fr> {
        match self {
            Self::Constant(c) => Some(c.value),
            Self::Variable(v) => v.value,
        }
    }
    pub fn lc<CS: ConstraintSystem<E>>(&self) -> LinearCombination<E> {
        match self {
            Self::Constant(c) => LinearCombination::zero() + (c.value.clone(), CS::one()),
            Self::Variable(v) => LinearCombination::zero() + v.variable,
        }
    }
}

pub fn biguint_to_fr<E: Engine>(biguint: BigUint) -> Option<E::Fr> {
    E::Fr::from_str(&biguint.to_str_radix(10))
}
