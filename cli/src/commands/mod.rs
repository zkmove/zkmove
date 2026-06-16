// Copyright (c) zkMove Authors

//! CLI command definitions (clap). Each command is a thin layer that parses arguments
//! and delegates the real work to the reusable [`crate::ops`] layer.

pub mod aptos;
pub mod poseidon;
pub mod sui;
pub mod vm;

pub use aptos::AptosCommands;
pub use poseidon::PoseidonCommand;
pub use sui::SuiCommands;
pub use vm::VmCommands;
