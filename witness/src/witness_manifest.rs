// Copyright (c) zkMove Authors

//! Manifest describing the witnesses generated for the functional tests.
//!
//! `zkmove vm run-all` writes one entry per `[circuit.*]` section of
//! `Move.toml`; the functional test suite uses it to build each circuit with
//! its own configuration instead of a single global `max_execution_rows`.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessManifest {
    /// Name of the Move package the witnesses were generated from.
    pub package: String,
    pub cases: Vec<WitnessCase>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessCase {
    /// Name of the `[circuit.<name>]` section (or "default" for plain `[circuit]`).
    pub name: String,
    /// Entry module id, formatted as `<address>::<module>`.
    pub module_id: String,
    pub function_name: String,
    /// Original argument strings from the circuit table.
    pub args: Vec<String>,
    pub max_execution_rows: usize,
    pub max_poseidon_rows: usize,
    /// Execution rows required by this witness (before padding), measured by
    /// `zkmove vm run-all`.
    #[serde(default)]
    pub execution_rows: usize,
    /// Witness file name, relative to the manifest.
    pub witness: String,
}
