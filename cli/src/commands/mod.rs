// Copyright (c) zkMove Authors

//! CLI command definitions (clap) and command-specific workflows.

pub mod aptos;
pub mod poseidon;
pub mod setup;
pub mod sui;
pub mod vm;

pub use aptos::AptosCommands;
pub use poseidon::PoseidonCommand;
pub use setup::SetupCommand;
pub use sui::SuiCommands;
pub use vm::VmCommands;
