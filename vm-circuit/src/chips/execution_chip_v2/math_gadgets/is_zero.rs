use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use types::Field;

/// Returns `1` when `value == 0`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsZeroGadget<F> {
    inverse: Cell<F>,
    value: Expression<F>,
    is_zero: Expression<F>,
}

impl<F: Field> IsZeroGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilderV2<F>, value: Expression<F>) -> Self {
        let inverse = cb.query_cell();
        let is_zero = 1u64.expr() - (value.clone() * inverse.expr());
        Self {
            inverse,
            is_zero,
            value,
        }
    }

    pub(crate) fn configure(&self) -> Vec<(&'static str, Expression<F>)> {
        vec![
            // when `value != 0` check `inverse = a.invert()`: value * (1 - value *
            // inverse)
            (
                "value ⋅ (1 - value ⋅ value_inv)",
                self.value.clone() * self.is_zero.clone(),
            ),
            // when `value == 0` check `inverse = 0`: `inverse ⋅ (1 - value *
            // inverse)`
            (
                "value_inv ⋅ (1 - value ⋅ value_inv)",
                self.inverse.expr() * self.is_zero.clone(),
            ),
        ]
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.is_zero.clone()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: F,
    ) -> Result<F, Error> {
        let inverse = value.invert().unwrap_or(F::ZERO);
        self.inverse.assign(region, offset, Value::known(inverse))?;
        Ok(if value.is_zero().into() {
            F::ONE
        } else {
            F::ZERO
        })
    }
}
