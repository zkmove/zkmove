// Copyright (c) zkMove Authors

use halo2_proofs::circuit::{Layouter, Value as CircuitValue};
use halo2_proofs::plonk::{Error, TableColumn};

use types::Field;

pub use gadgets::util::Expr;

pub(crate) trait SubInvert<F: Field> {
    fn sub_invert(&self, other: usize) -> Option<F>;
}

impl<F: Field> SubInvert<F> for usize {
    fn sub_invert(&self, other: usize) -> Option<F> {
        if *self == other {
            Some(F::ONE)
        } else {
            let delta = F::from_u128(*self as u128) - F::from_u128(other as u128);
            delta.invert().into()
        }
    }
}

pub(crate) trait DeltaInvert<F: Field> {
    fn delta_invert(&self, other: F) -> Option<F>;
}
impl<F: Field> DeltaInvert<F> for F {
    fn delta_invert(&self, other: F) -> Option<F> {
        if *self == other {
            Some(F::ONE)
        } else {
            let delta = *self - other;
            delta.invert().into()
        }
    }
}

// a special table with solo column and the value same as index.
// which is to garantuee value is among [0, max].
pub(crate) fn assign_index_table<F: Field>(
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
                .try_fold((), |_, res| res)
        },
    )?;
    Ok(())
}

/// Returns the sum of the passed in cells
pub mod sum {
    use crate::chips::utils::Expr;
    use halo2_proofs::plonk::Expression;
    use types::Field;

    /// Returns an expression for the sum of the list of expressions.
    #[allow(dead_code)]
    pub(crate) fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(
        inputs: I,
    ) -> Expression<F> {
        inputs
            .into_iter()
            .fold(0u64.expr(), |acc, input| acc + input.expr())
    }

    /// Returns the sum of the given list of values within the field.
    pub fn value<F: Field>(values: &[u8]) -> F {
        values
            .iter()
            .fold(F::ZERO, |acc, value| acc + F::from(*value as u64))
    }
}

/// Returns `1` when `expr[0] && expr[1] && ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod and {
    use crate::chips::utils::Expr;
    use halo2_proofs::plonk::Expression;
    use types::Field;

    /// Returns an expression that evaluates to 1 only if all the expressions in
    /// the given list are 1, else returns 0.
    #[allow(dead_code)]
    pub(crate) fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(
        inputs: I,
    ) -> Expression<F> {
        inputs
            .into_iter()
            .fold(1u64.expr(), |acc, input| acc * input.expr())
    }

    /// Returns the product of all given values.
    pub fn value<F: Field>(inputs: Vec<F>) -> F {
        inputs.iter().fold(F::ONE, |acc, input| acc * input)
    }
}

/// Returns `1` when `expr[0] || expr[1] || ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod or {
    use super::{and, not};
    use crate::chips::utils::Expr;
    use halo2_proofs::plonk::Expression;
    use types::Field;

    /// Returns an expression that evaluates to 1 if any expression in the given
    /// list is 1. Returns 0 if all the expressions were 0.
    #[allow(dead_code)]
    pub(crate) fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(
        inputs: I,
    ) -> Expression<F> {
        not::expr(and::expr(inputs.into_iter().map(not::expr)))
    }

    /// Returns the value after passing all given values through the OR gate.
    pub fn value<F: Field>(inputs: Vec<F>) -> F {
        not::value(and::value(inputs.into_iter().map(not::value).collect()))
    }
}

/// Returns `1` when `b == 0`, and returns `0` otherwise.
/// `b` needs to be boolean
pub mod not {
    use crate::chips::utils::Expr;
    use halo2_proofs::plonk::Expression;
    use types::Field;

    /// Returns an expression that represents the NOT of the given expression.
    pub(crate) fn expr<F: Field, E: Expr<F>>(b: E) -> Expression<F> {
        1u64.expr() - b.expr()
    }

    /// Returns a value that represents the NOT of the given value.
    pub fn value<F: Field>(b: F) -> F {
        F::ONE - b
    }
}

/// Returns `a ^ b`.
/// `a` and `b` needs to be boolean
pub mod xor {
    use crate::chips::utils::Expr;
    use halo2_proofs::plonk::Expression;
    use types::Field;

    /// Returns an expression that represents the XOR of the given expression.
    #[allow(dead_code)]
    pub(crate) fn expr<F: Field, E: Expr<F>>(a: E, b: E) -> Expression<F> {
        a.expr() + b.expr() - 2u64.expr() * a.expr() * b.expr()
    }

    /// Returns a value that represents the XOR of the given value.
    pub fn value<F: Field>(a: F, b: F) -> F {
        a + b - F::from(2u64) * a * b
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when
/// `selector == 0`. `selector` needs to be boolean.
pub mod select {
    use crate::chips::utils::Expr;
    use halo2_proofs::plonk::Expression;
    use types::Field;

    /// Returns the `when_true` expression when the selector is true, else
    /// returns the `when_false` expression.
    pub fn expr<F: Field>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        selector.clone() * when_true + (1u64.expr() - selector) * when_false
    }

    /// Returns the `when_true` value when the selector is true, else returns
    /// the `when_false` value.
    pub fn value<F: Field>(selector: F, when_true: F, when_false: F) -> F {
        selector * when_true + (F::ONE - selector) * when_false
    }

    /// Returns the `when_true` word when selector is true, else returns the
    /// `when_false` word.
    pub fn value_word<F: Field>(
        selector: F,
        when_true: [u8; 32],
        when_false: [u8; 32],
    ) -> [u8; 32] {
        if selector == F::ONE {
            when_true
        } else {
            when_false
        }
    }
}
