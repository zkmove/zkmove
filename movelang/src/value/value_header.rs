// Copyright (c) zkMove Authors

use crate::value::{PrimitiveValue, U128};
use halo2_proofs::arithmetic::FieldExt;
use std::marker::PhantomData;

#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct ValueHeader<F: FieldExt> {
    flattened_len: u16,
    len: u16,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ValueHeader<F> {
    pub fn new(flattened_len: usize, len: usize) -> Self {
        debug_assert!(flattened_len < u16::MAX as usize);
        debug_assert!(len < u16::MAX as usize);

        Self {
            flattened_len: flattened_len as u16,
            len: len as u16,
            _marker: PhantomData,
        }
    }

    // The content of the header is compressed into a field element in little-endian order.
    // bit[0..16],  flattened_len
    // bit[16..32], len
    pub fn value(&self) -> F {
        F::from_u128((self.flattened_len as u128) + ((self.len as u128) << 16))
    }
    pub fn flattened_len(&self) -> u16 {
        self.flattened_len
    }
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u16 {
        self.len
    }
}

impl<F: FieldExt> From<ValueHeader<F>> for PrimitiveValue<F> {
    fn from(value: ValueHeader<F>) -> PrimitiveValue<F> {
        PrimitiveValue::U128(U128(value.value()))
    }
}

impl<F: FieldExt> From<F> for ValueHeader<F> {
    fn from(value: F) -> ValueHeader<F> {
        let flattened_len = (value.get_lower_128() & 0xFFFF) as usize;
        let len = ((value.get_lower_128() & 0xFFFF0000) >> 16) as usize;
        Self::new(flattened_len, len)
    }
}
