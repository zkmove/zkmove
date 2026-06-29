// Copyright (c) zkMove Authors

//! Reusable, clap-free API shared by the CLI binary and SDK callers.
//!
//! Each module takes typed inputs and returns typed outputs, leaving argument parsing
//! and most file IO to the `commands` layer.

pub mod circuit;
pub mod poseidon;
pub mod prove;
pub mod setup;
pub mod verify;
pub mod witness;

pub use prove::{prove, ProveOutput};
pub use setup::{EntryArgument, VmCircuitContext};
pub use verify::verify;
pub use witness::generate_witness;
