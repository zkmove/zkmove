// Copyright (c) zkMove Authors

use halo2_proofs::plonk::Expression;
use std::convert::From;
use types::Field;

/// A header is added for the flattened value. Both value length and flattened value's length
/// are recorded in the header.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ValueHeader {
    flattened_len: u16,
    len: u16,
}

impl ValueHeader {
    pub fn new(flattened_len: usize, len: usize) -> Self {
        debug_assert!(flattened_len < u16::MAX as usize);
        debug_assert!(len < u16::MAX as usize);

        Self {
            flattened_len: flattened_len as u16,
            len: len as u16,
        }
    }

    // The content of the header is compressed into a field element in little-endian order.
    // bit[0..16],  flattened_len
    // bit[16..32], len
    pub fn value(&self) -> u128 {
        (self.flattened_len as u128) + ((self.len as u128) << 16)
    }
    pub fn field_value<F: Field>(&self) -> F {
        F::from_u128((self.flattened_len as u128) + ((self.len as u128) << 16))
    }
    pub fn expr<F: Field>(&self) -> Expression<F> {
        Expression::Constant(self.field_value())
    }
    pub fn flattened_len(&self) -> u16 {
        self.flattened_len
    }
    pub fn len(&self) -> u16 {
        self.len
    }

    pub fn members(&self) -> (u16, u16) {
        (self.flattened_len, self.len)
    }

    // default ValueHeader for any reference value
    pub fn default_for_ref_value() -> Self {
        Self::new(4, 3)
    }
}

impl<F: Field> From<F> for ValueHeader {
    fn from(value: F) -> ValueHeader {
        let flattened_len = (value.get_lower_128() & 0xFFFF) as usize;
        let len = ((value.get_lower_128() & 0xFFFF0000) >> 16) as usize;
        Self::new(flattened_len, len)
    }
}
