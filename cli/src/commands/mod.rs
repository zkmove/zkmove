// Copyright (c) zkMove Authors

//! CLI command definitions (clap) and command-specific workflows.

#[cfg(feature = "verifier")]
pub mod aptos;
pub mod poseidon;
#[cfg(feature = "verifier")]
pub mod sui;
pub mod vm;

#[cfg(feature = "verifier")]
pub use aptos::AptosCommands;
pub use poseidon::PoseidonCommand;
#[cfg(feature = "verifier")]
pub use sui::SuiCommands;
pub use vm::VmCommands;
