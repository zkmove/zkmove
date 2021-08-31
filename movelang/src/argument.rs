use anyhow::{Error, Result};
use move_core_types::parser::parse_transaction_arguments;
use std::str::FromStr;

pub use move_core_types::transaction_argument::TransactionArgument as ScriptArgument;
pub use move_vm_types::loaded_data::runtime_types::Type as MoveValueType;

#[derive(Debug, Clone)]
pub struct ScriptArguments(Vec<ScriptArgument>);

impl ScriptArguments {
    pub fn new(args: Vec<ScriptArgument>) -> Self {
        Self(args)
    }
    pub fn as_inner(&self) -> &Vec<ScriptArgument> {
        &self.0
    }
}

impl FromStr for ScriptArguments {
    type Err = Error;

    // convert from comma list
    fn from_str(input: &str) -> Result<Self> {
        Ok(ScriptArguments(parse_transaction_arguments(input)?))
    }
}
