use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::{Cell, CellType};
use field_exts::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{ErrorFront as Error, Expression};
use std::hash::{Hash, Hasher};

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

    pub fn assign_empty(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
    ) -> Result<(), Error> {
        self.cell.assign(region, offset, Value::known(F::ZERO))?;
        Ok(())
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
