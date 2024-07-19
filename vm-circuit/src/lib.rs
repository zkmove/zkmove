// Copyright (c) zkMove Authors
#![feature(lint_reasons)]

extern crate aptos_move_witnesses;
extern crate movelang;

pub mod chips;
pub mod circuit;
pub mod circuit_v2;
pub(crate) mod table;
mod utils;
pub mod witness;

pub use utils::{
    find_best_k, mock_prove_circuit, print_circuit_layout, proof_vm_circuit_kzg,
    prove_vm_circuit_ipa, prove_vm_circuit_kzg, setup_vm_circuit, verify_vm_circuit_kzg, MAX_K,
    MIN_K,
};
