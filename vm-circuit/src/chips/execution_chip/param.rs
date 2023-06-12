// Copyright (c) zkMove Authors
use std::cell::RefCell;

pub const BYTES_NUM: usize = 16;

pub const MAX_ADDRESS_EXT_LENGTH: usize = 8;

pub const STEP_CHIP_WIDTH: usize = 64;

pub const STEP_HEIGHT: usize = 40; // default max step height

pub const GENERIC_TYPE_CAPACITY: usize = 4;

thread_local!(pub static WORD_CAPACITY: RefCell<usize> = RefCell::new(8));

pub fn word_capacity() -> usize {
    WORD_CAPACITY.with(|f| *f.borrow())
}
