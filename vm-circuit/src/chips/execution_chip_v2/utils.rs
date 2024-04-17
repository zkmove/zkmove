use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::{Cell, CellType};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{Error, Expression};
use std::hash::{Hash, Hasher};
use types::Field;

#[derive(Debug, Clone)]
pub struct StoredExpression<F> {
    pub(crate) name: String,
    pub(crate) cell: Cell<F>,
    pub(crate) cell_type: CellType,
    pub(crate) expr: Expression<F>,
    pub(crate) expr_id: String,
}

impl<F> Hash for StoredExpression<F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.expr_id.hash(state);
        self.cell_type.hash(state);
    }
}

/// Evaluate an expression using a `CachedRegion` at `offset`.
pub(crate) fn evaluate_expression<F: Field>(
    expr: &Expression<F>,
    region: &CachedRegion<'_, '_, F>,
    offset: usize,
) -> Value<F> {
    expr.evaluate(
        &|scalar| Value::known(scalar),
        &|_| unimplemented!("selector column"),
        &|fixed_query| {
            Value::known(region.get_fixed(
                offset,
                fixed_query.column_index(),
                fixed_query.rotation(),
            ))
        },
        &|advice_query| {
            Value::known(region.get_advice(
                offset,
                advice_query.column_index(),
                advice_query.rotation(),
            ))
        },
        &|_| unimplemented!("instance column"),
        &|challenge| *region.challenges().indexed()[challenge.index()],
        &|a| -a,
        &|a, b| a + b,
        &|a, b| a * b,
        &|a, scalar| a * Value::known(scalar),
    )
}

impl<F: Field> StoredExpression<F> {
    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
    ) -> Result<Value<F>, Error> {
        let value = evaluate_expression(&self.expr, region, offset);
        self.cell.assign(region, offset, value)?;
        Ok(value)
    }
}
/// Maximum number of bytes that an integer can fit in field without wrapping
/// around.
pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

/// Decodes a field element from its byte representation in little endian order
pub(crate) mod from_bytes {
    use super::MAX_N_BYTES_INTEGER;
    use gadgets::util::Expr;
    use halo2_proofs::plonk::Expression;
    use types::Field;

    pub(crate) fn expr<F: Field, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
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

    pub(crate) fn value<F: Field>(bytes: &[u8]) -> F {
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

/// Transposes an `Value` of a [`Result`] into a [`Result`] of an `Value`.
pub(crate) fn transpose_val_ret<F, E>(value: Value<Result<F, E>>) -> Result<Value<F>, E> {
    let mut ret = Ok(Value::unknown());
    value.map(|value| {
        ret = value.map(Value::known);
    });
    ret
}
