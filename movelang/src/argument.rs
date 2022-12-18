// Copyright (c) zkMove Authors

use anyhow::{Error, Result};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use move_core_types::parser::parse_transaction_arguments;
use std::str::FromStr;

use crate::account_address::AccountAddress;
use crate::utility::MoveValueType;
pub use move_core_types::parser::parse_transaction_argument;
pub use move_core_types::transaction_argument::TransactionArgument as ScriptArgument;

#[derive(Debug, Clone)]
pub struct ScriptArguments(Vec<ScriptArgument>);

impl ScriptArguments {
    pub fn new(args: Vec<ScriptArgument>) -> Self {
        Self(args)
    }
    pub fn as_inner(&self) -> &Vec<ScriptArgument> {
        &self.0
    }
    pub fn into_inner(self) -> Vec<ScriptArgument> {
        self.0
    }
}

impl FromStr for ScriptArguments {
    type Err = Error;

    // convert from comma list
    fn from_str(input: &str) -> Result<Self> {
        Ok(ScriptArguments(parse_transaction_arguments(input)?))
    }
}

pub fn convert_from<F: FieldExt>(arg: ScriptArgument) -> VmResult<F> {
    match arg {
        ScriptArgument::U8(v) => Ok(F::from_u128(v as u128)),
        ScriptArgument::U64(v) => Ok(F::from_u128(v as u128)),
        ScriptArgument::U128(v) => Ok(F::from_u128(v)),
        ScriptArgument::Bool(v) => Ok(if v { F::one() } else { F::zero() }),
        ScriptArgument::Address(v) => Ok(AccountAddress::from(v).value()),
        _ => Err(RuntimeError::new(StatusCode::UnsupportedMoveType)),
    }
}

pub fn argument_type(arg: &ScriptArgument) -> VmResult<MoveValueType> {
    match arg {
        ScriptArgument::U8(_) => Ok(MoveValueType::U8),
        ScriptArgument::U64(_) => Ok(MoveValueType::U64),
        ScriptArgument::U128(_) => Ok(MoveValueType::U128),
        ScriptArgument::Bool(_) => Ok(MoveValueType::Bool),
        ScriptArgument::Address(_) => Ok(MoveValueType::Address),
        _ => Err(RuntimeError::new(StatusCode::UnsupportedMoveType)),
    }
}
