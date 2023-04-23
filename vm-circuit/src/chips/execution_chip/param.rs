// Copyright (c) zkMove Authors
use crate::chips::execution_chip::opcode::Opcode;
use crate::circuit::VmCircuit;
use halo2_proofs::{
    pasta::Fp,
    plonk::{Circuit, ConstraintSystem},
};
use std::collections::HashMap;

pub const BYTES_NUM: usize = 16;

pub const STEP_CHIP_WIDTH: usize = 80;

pub const STEP_HEIGHT: usize = 17; // default max step height

pub const WORD_CAPACITY: usize = 16; // max(#method_arguments, #flattened_struct_fields)

lazy_static::lazy_static! {
    // Step slot height in evm circuit
    pub(crate) static ref STEP_SLOT_HEIGHT_MAP : HashMap<Opcode, usize> = get_step_height_map();
}
fn get_step_height_map() -> HashMap<Opcode, usize> {
    let mut meta = ConstraintSystem::<Fp>::default();
    let circuit = VmCircuit::configure(&mut meta);

    circuit.execution_chip_config.height_map
}
