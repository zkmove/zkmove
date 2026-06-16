// Copyright (c) zkMove Authors

//! Library surface for the zkMove CLI.
//!
//! The crate is split into three layers so that both the `zkmove` binary and future
//! SDK callers can reuse the same logic:
//!
//! - [`common`]: shared helpers (package loading, Move.toml parsing, encoding utilities).
//! - [`ops`]: clap-free operations (witness generation, proving, verification) that take
//!   typed inputs and return typed outputs.
//! - [`commands`]: clap command definitions that parse arguments and delegate to `ops`.

pub mod commands;
pub mod common;
pub mod ops;

// Re-export common helpers at the crate root for backwards compatibility with the
// command modules that reference `crate::<helper>`.
pub use common::*;
