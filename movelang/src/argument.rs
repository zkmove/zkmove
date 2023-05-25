// Copyright (c) zkMove Authors

use anyhow::{Error, Result};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use move_binary_format::normalized::Type;
use move_core_types::language_storage::TypeTag;
use move_core_types::parser::parse_transaction_arguments;

use std::str::FromStr;

use crate::account_address::AccountAddress;
use crate::utility::MoveValueType;
pub use move_core_types::parser::parse_transaction_argument;
pub use move_core_types::parser::parse_type_tags;
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

#[derive(Debug, Clone)]
pub struct Signer(ScriptArgument);

impl FromStr for Signer {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Ok(Signer(parse_transaction_argument(input)?))
    }
}

impl Signer {
    pub fn into_inner(self) -> ScriptArgument {
        self.0
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

pub fn convert_type_tag_to_type(t: TypeTag) -> Type {
    match t {
        TypeTag::Bool => Type::Bool,
        TypeTag::U8 => Type::U8,
        TypeTag::U64 => Type::U64,
        TypeTag::U128 => Type::U128,
        TypeTag::Address => Type::Address,
        TypeTag::Signer => Type::Signer,
        TypeTag::Vector(sub_t) => Type::Vector(Box::new(convert_type_tag_to_type(*sub_t))),
        TypeTag::Struct(struct_tag) => Type::Struct {
            address: struct_tag.address,
            module: struct_tag.module,
            name: struct_tag.name,
            type_arguments: struct_tag
                .type_params
                .into_iter()
                .map(convert_type_tag_to_type)
                .collect(),
        },
        TypeTag::U16 => Type::U16,
        TypeTag::U32 => Type::U32,
        TypeTag::U256 => Type::U256,
    }
}
