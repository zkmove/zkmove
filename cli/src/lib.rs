// Copyright (c) zkMove Authors

//! Library surface for the zkMove CLI.
//!
//! The crate is split so that the CLI owns command-specific behavior while shared
//! witness/proving/verification routines remain reusable:
//!
//! - [`common`]: shared helpers (package loading, Move.toml parsing, encoding utilities).
//! - [`api`]: clap-free SDK API for logic that is shared across commands.
//! - [`commands`]: clap command definitions and command-specific workflows.

pub mod api;
pub mod commands;
pub mod common;

// Re-export common helpers at the crate root for backwards compatibility with the
// command modules that reference `crate::<helper>`.
pub use common::*;
