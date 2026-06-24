// Copyright (c) zkMove Authors

//! Reusable, clap-free API shared by the CLI binary and SDK callers.
//!
//! Each module takes typed inputs and returns typed outputs, leaving argument parsing
//! and most file IO to the `commands` layer.

pub mod circuit;
pub mod context;
pub mod dry_run;
pub mod poseidon;
pub mod prove;
pub mod verify;

pub use context::{EntryArgument, VmCircuitContext};
pub use dry_run::dry_run;
pub use prove::{prove, ProveOutput};
pub use verify::verify;
