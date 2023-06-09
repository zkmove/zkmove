// Copyright (c) zkMove Authors
use crate::witness::CircuitConfig;

pub const BYTES_NUM: usize = 16;

pub const MAX_ADDRESS_EXT_LENGTH: usize = 8;

pub const STEP_CHIP_WIDTH: usize = 64;

pub const STEP_HEIGHT: usize = 40; // default max step height

pub const GENERIC_TYPE_CAPACITY: usize = 4;

lazy_static::lazy_static! {
    pub(crate) static ref WORD_CAPACITY : usize = CircuitConfig::word_capacity_get();
}
