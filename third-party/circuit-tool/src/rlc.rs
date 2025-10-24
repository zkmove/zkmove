use std::ops::{Add, Mul};
/// Returns the random linear combination of the inputs.
/// Encoding is done as follows: v_0 * R^0 + v_1 * R^1 + ...
use util::Expr;

use field_exts::Field;
use halo2_proofs::plonk::Expression;

pub fn expr<F: Field, E: Expr<F>>(expressions: &[E], randomness: E) -> Expression<F> {
    if !expressions.is_empty() {
        generic(expressions.iter().map(|e| e.expr()), randomness.expr())
    } else {
        0.expr()
    }
}

pub fn value<'a, F: Field, I>(values: I, randomness: F) -> F
where
    I: IntoIterator<Item = &'a u8>,
    <I as IntoIterator>::IntoIter: DoubleEndedIterator,
{
    let values = values
        .into_iter()
        .map(|v| F::from(*v as u64))
        .collect::<Vec<F>>();
    if !values.is_empty() {
        generic(values, randomness)
    } else {
        F::ZERO
    }
}

pub fn generic<V, I>(values: I, randomness: V) -> V
where
    I: IntoIterator<Item = V>,
    <I as IntoIterator>::IntoIter: DoubleEndedIterator,
    V: Clone + Add<Output = V> + Mul<Output = V>,
{
    let mut values = values.into_iter().rev();
    let init = values.next().expect("values should not be empty");

    values.fold(init, |acc, value| acc * randomness.clone() + value)
}
