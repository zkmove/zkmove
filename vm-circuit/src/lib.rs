// Copyright (c) zkMove Authors
#![feature(lint_reasons)]
#![feature(associated_type_defaults)]
#![feature(slice_as_chunks)]

extern crate aptos_move_witnesses;
extern crate move_core_types;
extern crate move_vm_runtime;
extern crate movelang;

pub mod chips;
pub mod circuit_v2;
pub(crate) mod table;
mod utils;
pub mod witness;

pub use utils::{
    mock_prove_circuit, print_circuit_layout, prove_and_verify_circuit_ipa, prove_and_verify_kzg,
    setup_circuit, verify_circuit_kzg, SubCircuit, SubCircuitConfig, MAX_K, MIN_K,
};
