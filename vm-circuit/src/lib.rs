// Copyright (c) zkMove Authors
#![feature(associated_type_defaults)]
#![feature(slice_as_chunks)]
#![allow(non_camel_case_types)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::wrong_self_convention)]
#![allow(dead_code)]
#![allow(unused_variables)]
extern crate aptos_move_witnesses;
extern crate move_core_types;
extern crate move_vm_runtime;
extern crate movelang;

pub mod chips;
pub mod circuit_v2;
pub(crate) mod poseidon_circuit;
pub(crate) mod table;
mod utils;

pub use aptos_move_witnesses::static_info::Footprints;
pub use chips::execution_chip_v2::instance::{InstanceFields, NUM_INSTANCE_COLUMNS};
pub use circuit_v2::{CircuitConfigV2, VmCircuit};
pub use utils::{
    best_k, mock_prove_circuit, print_cs_info, prove_circuit, setup_circuit, verify_circuit,
    EntryInfo, ModuleIdMapping, SubCircuit, SubCircuitConfig, KZG, MAX_DEGREE, MIN_DEGREE,
};
