// Copyright (c) zkMove Authors

//! Reusable, clap-free operations shared by the CLI binary and (future) SDK callers.
//!
//! Each module takes typed inputs and returns typed outputs, leaving argument parsing
//! and most file IO to the `commands` layer.

pub mod aptos;
pub mod circuit;
pub mod poseidon;
pub mod prove;
pub mod run;
pub mod sui;
pub mod test_verifier;
pub mod verify;
