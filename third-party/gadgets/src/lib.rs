//! # ZKEVM-Gadgets
//!
//! A collection of reusable gadgets for the zk_evm circuits.

#![allow(clippy::upper_case_acronyms)]

pub mod add;
pub mod comparison;
pub mod is_zero;
pub mod lt;
pub mod mul_add;
pub mod range_check;

use field_exts::Field;
use halo2_proofs::plonk::Expression;

pub const NUM_OF_BYTES_U128: usize = 16;

/// Restrict an expression to be a boolean.
pub fn bool_check<F: Field>(value: Expression<F>) -> Expression<F> {
    range_check(value, 2)
}

/// Restrict an expression such that 0 <= word < range.
pub fn range_check<F: Field>(word: Expression<F>, range: usize) -> Expression<F> {
    (1..range).fold(word.clone(), |acc, i| {
        acc * (Expression::Constant(F::from(i as u64)) - word.clone())
    })
}
