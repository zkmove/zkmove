// Copyright (c) zkMove Authors
use crate::witness::DEFAULT_WORD_CAPACITY;
use std::cell::RefCell;

pub const BYTES_NUM: usize = 16;

pub const MAX_ADDRESS_EXT_LENGTH: usize = 8;

pub const STEP_CHIP_WIDTH: usize = 64;

pub const STEP_HEIGHT: usize = 40; // default max step height

pub const GENERIC_TYPE_CAPACITY: usize = 4;

thread_local!(pub static WORD_CAPACITY: RefCell<usize> = RefCell::new(DEFAULT_WORD_CAPACITY));

#[inline]
pub fn word_capacity() -> usize {
    WORD_CAPACITY.with(|f| *f.borrow())
}

#[inline]
pub fn set_word_capacity(word_capacity: usize) {
    WORD_CAPACITY.with(|f| {
        *f.borrow_mut() = word_capacity;
    })
}

// TODO: static parse the length
// To constrain the function call we need to flatten all the arguments
// and assign them to a set of cells. This constant is used to represent
// the maximum number of the cells.
pub const NUM_OF_ARGS_CELLS: usize = 32;

/// Maximum number of bytes that an integer can fit in field without wrapping
/// around.
pub const MAX_N_BYTES_INTEGER: usize = 31;
