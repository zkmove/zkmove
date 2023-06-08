// Copyright (c) zkMove Authors
use crate::witness::CircuitConfig;

pub const BYTES_NUM: usize = 16;

pub const MAX_ADDRESS_EXT_LENGTH: usize = 8;

pub const STEP_CHIP_WIDTH: usize = 64;

pub const STEP_HEIGHT: usize = 40; // default max step height

// pub const WORD_CAPACITY: usize = 16; // max(#method_arguments, #flattened_struct_fields)

pub const GENERIC_TYPE_CAPACITY: usize = 4;

lazy_static::lazy_static! {
    // Step slot height in evm circuit
    pub(crate) static ref WORD_CAPACITY : usize = CircuitConfig::default().get_word_size();
}
