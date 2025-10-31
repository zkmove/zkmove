//! Utility traits, functions used in the crate.
use crate::Field;
use halo2_proofs::plonk::Expression;

/// Returns the sum of the passed in cells
pub mod sum {
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns an expression for the sum of the list of expressions.
    pub fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs
            .into_iter()
            .fold(0.expr(), |acc, input| acc + input.expr())
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
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns an expression that evaluates to 1 only if all the expressions in
    /// the given list are 1, else returns 0.
    pub fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs
            .into_iter()
            .fold(1.expr(), |acc, input| acc * input.expr())
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
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns an expression that evaluates to 1 if any expression in the given
    /// list is 1. Returns 0 if all the expressions were 0.
    pub fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
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
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns an expression that represents the NOT of the given expression.
    pub fn expr<F: Field, E: Expr<F>>(b: E) -> Expression<F> {
        1.expr() - b.expr()
    }

    /// Returns a value that represents the NOT of the given value.
    pub fn value<F: Field>(b: F) -> F {
        F::ONE - b
    }
}

/// Returns `a ^ b`.
/// `a` and `b` needs to be boolean
pub mod xor {
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns an expression that represents the XOR of the given expression.
    pub fn expr<F: Field, E: Expr<F>>(a: E, b: E) -> Expression<F> {
        a.expr() + b.expr() - 2.expr() * a.expr() * b.expr()
    }

    /// Returns a value that represents the XOR of the given value.
    pub fn value<F: Field>(a: F, b: F) -> F {
        a + b - F::from(2u64) * a * b
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when
/// `selector == 0`. `selector` needs to be boolean.
pub mod select {
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns the `when_true` expression when the selector is true, else
    /// returns the `when_false` expression.
    pub fn expr<F: Field>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        selector.clone() * when_true + (1.expr() - selector) * when_false
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

/// Returns the power of a number using straightforward multiplications
pub mod pow {
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    use super::Scalar;

    /// Raises `value` to the power of `exponent`
    pub fn expr<F: Field>(value: Expression<F>, exponent: usize) -> Expression<F> {
        let mut result = 1.expr();
        for _ in 0..exponent {
            result = result * value.expr();
        }
        result
    }

    /// Raises `value` to the power of `exponent`
    pub fn value<F: Field>(value: F, exponent: usize) -> F {
        let mut result = 1.scalar();
        for _ in 0..exponent {
            result *= value;
        }
        result
    }
}

/// Decodes a field element from its byte representation in little endian order
pub mod from_bytes {
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;
    /// Maximum number of bytes that an integer can fit in field without wrapping
    /// around.
    pub const MAX_N_BYTES_INTEGER: usize = 31;

    pub fn expr<F: Field, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
        debug_assert!(
            bytes.len() <= MAX_N_BYTES_INTEGER,
            "Too many bytes to compose an integer in field"
        );
        let mut value = 0.expr();
        let mut multiplier = F::ONE;
        for byte in bytes.iter() {
            value = value + byte.expr() * multiplier;
            multiplier *= F::from(256);
        }
        value
    }

    pub fn value<F: Field>(bytes: &[u8]) -> F {
        debug_assert!(
            bytes.len() <= MAX_N_BYTES_INTEGER,
            "Too many bytes to compose an integer in field"
        );
        let mut value = F::ZERO;
        let mut multiplier = F::ONE;
        for byte in bytes.iter() {
            value += F::from(*byte as u64) * multiplier;
            multiplier *= F::from(256);
        }
        value
    }
}

/// Decodes a field element from its 4, 8 or 16 bits limbs representation in little endian order
pub mod from_limbs {
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    pub fn expr<F: Field, E: Expr<F>, const LIMB_BITS: usize>(limbs: &[E]) -> Expression<F> {
        debug_assert!(
            limbs.len() <= 255 / LIMB_BITS,
            "Too many limbs to compose an integer in field"
        );
        debug_assert!(
            LIMB_BITS == 4 || LIMB_BITS == 8 || LIMB_BITS == 16,
            "Only 4-bits, 8-bits or 16-bits limbs supported"
        );
        let mut value = 0.expr();
        let mut multiplier = F::ONE;
        for limb in limbs.iter() {
            value = value + limb.expr() * multiplier;
            multiplier *= F::from(1u64 << LIMB_BITS);
        }
        value
    }

    pub fn value<F: Field, const LIMB_BITS: usize>(limbs: &[u64]) -> F {
        debug_assert!(
            limbs.len() <= 255 / LIMB_BITS,
            "Too many limbs to compose an integer in field"
        );
        debug_assert!(
            LIMB_BITS == 4 || LIMB_BITS == 8 || LIMB_BITS == 16,
            "Only 4-bits, 8-bits or 16-bits limbs supported"
        );
        let mut value = F::ZERO;
        let mut multiplier = F::ONE;
        for limb in limbs.iter() {
            value += F::from(*limb) * multiplier;
            multiplier *= F::from(1u64 << LIMB_BITS);
        }
        value
    }
}

/// Trait that implements functionality to get a scalar from
/// commonly used types.
pub trait Scalar<F: Field> {
    /// Returns a scalar for the type.
    fn scalar(&self) -> F;
}

/// Implementation trait `Scalar` for type able to be casted to u64
#[macro_export]
macro_rules! impl_scalar {
    ($type:ty) => {
        impl<F: crate::Field> $crate::util::Scalar<F> for $type {
            #[inline]
            fn scalar(&self) -> F {
                F::from(*self as u64)
            }
        }
    };
    ($type:ty, $method:path) => {
        impl<F: crate::Field> $crate::Scalar<F> for $type {
            #[inline]
            fn scalar(&self) -> F {
                F::from($method(self) as u64)
            }
        }
    };
}

impl<F: Field> Scalar<F> for i32 {
    #[inline]
    fn scalar(&self) -> F {
        F::from(self.unsigned_abs() as u64) * if self.is_negative() { -F::ONE } else { F::ONE }
    }
}

impl<F: Field> Scalar<F> for &F {
    #[inline]
    fn scalar(&self) -> F {
        *(*self)
    }
}

/// Trait that implements functionality to get a constant expression from
/// commonly used types.
pub trait Expr<F: Field> {
    /// Returns an expression for the type.
    fn expr(&self) -> Expression<F>;
}

/// Implementation trait `Expr` for type able to be casted to u64
#[macro_export]
macro_rules! impl_expr {
    ($type:ty) => {
        $crate::impl_scalar!($type);
        impl<F: crate::Field> $crate::util::Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from(*self as u64))
            }
        }
    };
    ($type:ty, $method:path) => {
        $crate::impl_scalar!($type, $method);
        impl<F: crate::Field> $crate::util::Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from($method(self) as u64))
            }
        }
    };
}

impl_expr!(bool);
impl_expr!(u8);
impl_expr!(u64);
impl_expr!(usize);
impl_expr!(isize);

impl<F: Field> Expr<F> for i32 {
    #[inline]
    fn expr(&self) -> Expression<F> {
        Expression::Constant(self.scalar())
    }
}

impl<F: Field> Expr<F> for Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        self.clone()
    }
}

impl<F: Field> Expr<F> for &Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        (*self).clone()
    }
}

/// Given a bytes-representation of an expression, it computes and returns the
/// single expression.
pub fn expr_from_bytes<F: Field, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
    let mut value = 0.expr();
    let mut multiplier = F::ONE;
    for byte in bytes.iter() {
        value = value + byte.expr() * multiplier;
        multiplier *= F::from(256);
    }
    value
}

/// Returns 2**by as Field
pub fn pow_of_two<F: Field>(by: usize) -> F {
    F::from(2).pow([by as u64, 0, 0, 0])
}

/// Returns 2**by as Expression
pub fn pow_of_two_expr<F: Field>(by: usize) -> Expression<F> {
    Expression::Constant(pow_of_two(by))
}
