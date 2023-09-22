// Copyright (c) zkMove Authors

use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Region};
use halo2_proofs::circuit::{Layouter, Value as CircuitValue};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, TableColumn, VirtualCells};
use halo2_proofs::poly::Rotation;
use movelang::value::NUM_OF_BYTES_U128;
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub struct Cell<F> {
    pub expression: Expression<F>,
    pub column: Column<Advice>,
    pub rotation: Rotation,
}
impl<F: FieldExt> Expr<F> for Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

impl<F: FieldExt> Expr<F> for &Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}
impl<F: FieldExt> Cell<F> {
    pub fn new(meta: &mut VirtualCells<F>, column: Column<Advice>, rotation: i32) -> Self {
        Cell {
            expression: meta.query_advice(column, Rotation(rotation)),
            column,
            rotation: Rotation(rotation),
        }
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Option<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice(
            || "assign cell",
            self.column,
            (offset as i32 + self.rotation.0) as usize,
            || match value {
                Some(v) => CircuitValue::known(v),
                None => CircuitValue::unknown(),
            },
        )
    }

    pub fn assign_equality(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        cell: AssignedCell<F, F>,
        annotation: &str,
    ) -> Result<AssignedCell<F, F>, Error> {
        cell.copy_advice(
            || annotation,
            region,
            self.column,
            (offset as i32 + self.rotation.0) as usize,
        )
    }
}

pub(crate) trait Expr<F: FieldExt> {
    fn expr(&self) -> Expression<F>;
}
impl<F: FieldExt> Expr<F> for Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        self.clone()
    }
}

impl<F: FieldExt> Expr<F> for &Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        (*self).clone()
    }
}

impl<F: FieldExt> Expr<F> for i32 {
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from(*self as u64))
    }
}

impl<F: FieldExt> Expr<F> for usize {
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from(*self as u64))
    }
}

impl<F: FieldExt> Expr<F> for u64 {
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from(*self))
    }
}

// The internal representation of FieldExt is four 64-bits unsigned integer in little-endian order,
// This struct has 16 Cells, to hold the 16 bytes of the lower two u64.
pub struct FieldBytes<F: FieldExt>(pub(crate) [Cell<F>; 16]);

impl<F: FieldExt> From<Vec<Cell<F>>> for FieldBytes<F> {
    fn from(bytes: Vec<Cell<F>>) -> FieldBytes<F> {
        let bytes: [Cell<F>; 16] = bytes.try_into().unwrap_or_else(|v: Vec<Cell<F>>| {
            panic!(
                "Expected a Vec of length {} but it was {}",
                NUM_OF_BYTES_U128,
                v.len()
            )
        });
        FieldBytes(bytes)
    }
}

impl<F: FieldExt> Expr<F> for FieldBytes<F> {
    fn expr(&self) -> Expression<F> {
        let mut value = 0.expr();
        let mut multiplier = F::one();
        for byte in self.0.iter() {
            value = value + byte.expression.clone() * multiplier;
            multiplier *= F::from(256);
        }
        value
    }
}

impl<F: FieldExt> FieldBytes<F> {
    pub fn expr_with_n(&self, num: usize) -> Expression<F> {
        let mut value = 0.expr();
        let mut multiplier = F::one();
        for byte in self.0.iter().take(num) {
            value = value + byte.expression.clone() * multiplier;
            multiplier *= F::from(256);
        }
        value
    }

    pub fn expr_16bit(&self, num: usize) -> Expression<F> {
        let mut value = 0.expr();
        let mut multiplier = F::one();
        for byte in self.0.iter().take(num) {
            value = value + byte.expression.clone() * multiplier;
            multiplier *= F::from(1 << 16);
        }
        value
    }
}

// Decodes a field element from its byte representation
pub(crate) mod from_bytes {
    use super::Expr;
    use crate::chips::execution_chip::param::MAX_N_BYTES_INTEGER;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
        debug_assert!(
            bytes.len() <= MAX_N_BYTES_INTEGER,
            "Too many bytes to compose an integer in field"
        );
        let mut value = 0.expr();
        let mut multiplier = F::one();
        for byte in bytes.iter() {
            value = value + byte.expr() * multiplier;
            multiplier *= F::from(256);
        }
        value
    }

    #[allow(dead_code)]
    pub(crate) fn value<F: FieldExt>(bytes: &[u8]) -> F {
        debug_assert!(
            bytes.len() <= MAX_N_BYTES_INTEGER,
            "Too many bytes to compose an integer in field"
        );
        let mut value = F::zero();
        let mut multiplier = F::one();
        for byte in bytes.iter() {
            value += F::from(*byte as u64) * multiplier;
            multiplier *= F::from(256);
        }
        value
    }
}

pub(crate) trait SubInvert<F: FieldExt> {
    fn sub_invert(&self, other: usize) -> Option<F>;
}

impl<F: FieldExt> SubInvert<F> for usize {
    fn sub_invert(&self, other: usize) -> Option<F> {
        if *self == other {
            Some(F::one())
        } else {
            let delta = F::from_u128(*self as u128) - F::from_u128(other as u128);
            delta.invert().into()
        }
    }
}

pub(crate) trait DeltaInvert<F: FieldExt> {
    fn delta_invert(&self, other: F) -> Option<F>;
}
impl<F: FieldExt> DeltaInvert<F> for F {
    fn delta_invert(&self, other: F) -> Option<F> {
        if *self == other {
            Some(F::one())
        } else {
            let delta = *self - other;
            delta.invert().into()
        }
    }
}

// a special table with solo column and the value same as index.
// which is to garantuee value is among [0, max].
pub(crate) fn assign_index_table<F: FieldExt>(
    layouter: &mut impl Layouter<F>,
    table_name: &str,
    column: TableColumn,
    max_row: usize,
) -> Result<(), Error> {
    layouter.assign_table(
        || format!("{:?}", table_name),
        |mut table_column| {
            (0..=max_row)
                .map(|i| {
                    table_column.assign_cell(
                        || format!("{}[{}]", table_name, i),
                        column,
                        i,
                        || CircuitValue::known(F::from_u128(i as u128)),
                    )
                })
                .fold(Ok(()), |acc, res| acc.and(res))
        },
    )?;
    Ok(())
}

/// Returns the sum of the passed in cells
pub mod sum {
    use crate::chips::utilities::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression for the sum of the list of expressions.
    #[allow(dead_code)]
    pub(crate) fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(
        inputs: I,
    ) -> Expression<F> {
        inputs
            .into_iter()
            .fold(0.expr(), |acc, input| acc + input.expr())
    }

    /// Returns the sum of the given list of values within the field.
    pub fn value<F: FieldExt>(values: &[u8]) -> F {
        values
            .iter()
            .fold(F::zero(), |acc, value| acc + F::from(*value as u64))
    }
}

/// Returns `1` when `expr[0] && expr[1] && ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod and {
    use crate::chips::utilities::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that evaluates to 1 only if all the expressions in
    /// the given list are 1, else returns 0.
    #[allow(dead_code)]
    pub(crate) fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(
        inputs: I,
    ) -> Expression<F> {
        inputs
            .into_iter()
            .fold(1.expr(), |acc, input| acc * input.expr())
    }

    /// Returns the product of all given values.
    pub fn value<F: FieldExt>(inputs: Vec<F>) -> F {
        inputs.iter().fold(F::one(), |acc, input| acc * input)
    }
}

/// Returns `1` when `expr[0] || expr[1] || ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod or {
    use super::{and, not};
    use crate::chips::utilities::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that evaluates to 1 if any expression in the given
    /// list is 1. Returns 0 if all the expressions were 0.
    #[allow(dead_code)]
    pub(crate) fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(
        inputs: I,
    ) -> Expression<F> {
        not::expr(and::expr(inputs.into_iter().map(not::expr)))
    }

    /// Returns the value after passing all given values through the OR gate.
    pub fn value<F: FieldExt>(inputs: Vec<F>) -> F {
        not::value(and::value(inputs.into_iter().map(not::value).collect()))
    }
}

/// Returns `1` when `b == 0`, and returns `0` otherwise.
/// `b` needs to be boolean
pub mod not {
    use crate::chips::utilities::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that represents the NOT of the given expression.
    pub(crate) fn expr<F: FieldExt, E: Expr<F>>(b: E) -> Expression<F> {
        1.expr() - b.expr()
    }

    /// Returns a value that represents the NOT of the given value.
    pub fn value<F: FieldExt>(b: F) -> F {
        F::one() - b
    }
}

/// Returns `a ^ b`.
/// `a` and `b` needs to be boolean
pub mod xor {
    use crate::chips::utilities::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that represents the XOR of the given expression.
    #[allow(dead_code)]
    pub(crate) fn expr<F: FieldExt, E: Expr<F>>(a: E, b: E) -> Expression<F> {
        a.expr() + b.expr() - 2.expr() * a.expr() * b.expr()
    }

    /// Returns a value that represents the XOR of the given value.
    pub fn value<F: FieldExt>(a: F, b: F) -> F {
        a + b - F::from(2u64) * a * b
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when
/// `selector == 0`. `selector` needs to be boolean.
pub mod select {
    use crate::chips::utilities::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns the `when_true` expression when the selector is true, else
    /// returns the `when_false` expression.
    pub fn expr<F: FieldExt>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        selector.clone() * when_true + (1.expr() - selector) * when_false
    }

    /// Returns the `when_true` value when the selector is true, else returns
    /// the `when_false` value.
    pub fn value<F: FieldExt>(selector: F, when_true: F, when_false: F) -> F {
        selector * when_true + (F::one() - selector) * when_false
    }

    /// Returns the `when_true` word when selector is true, else returns the
    /// `when_false` word.
    pub fn value_word<F: FieldExt>(
        selector: F,
        when_true: [u8; 32],
        when_false: [u8; 32],
    ) -> [u8; 32] {
        if selector == F::one() {
            when_true
        } else {
            when_false
        }
    }
}
