// Copyright (c) zkMove Authors
#![feature(associated_type_defaults)]
#![feature(slice_as_chunks)]
#![allow(non_camel_case_types)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::wrong_self_convention)]
#![allow(dead_code)]

pub(crate) mod execution_circuit;
pub(crate) mod gadgets;
pub(crate) mod poseidon_circuit;
pub(crate) mod table;
pub(crate) mod utils;

pub mod proofs;
pub mod public_inputs;
pub mod vm_circuit;
