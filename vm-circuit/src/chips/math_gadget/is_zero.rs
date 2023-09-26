use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Region, Value as CircuitValue};
use halo2_proofs::plonk::{Error, Expression};

/// Returns `1` when `value == 0`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsZeroGadget<F> {
    inverse: Cell<F>,
    value: Expression<F>,
    is_zero: Expression<F>,
}

impl<F: FieldExt> IsZeroGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>, value: Expression<F>) -> Self {
        let inverse = cb.alloc_cell();
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
        region: &mut Region<'_, F>,
        offset: usize,
        value: F,
    ) -> Result<F, Error> {
        let inverse = value.invert().unwrap_or(F::zero());
        self.inverse.assign(region, offset, Some(inverse))?;
        Ok(if value.is_zero().into() {
            F::one()
        } else {
            F::zero()
        })
    }

    #[allow(dead_code)]
    pub(crate) fn assign_value(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: CircuitValue<F>,
    ) -> Result<CircuitValue<F>, Error> {
        let mut ret = Ok(CircuitValue::unknown());
        value.map(|v| {
            ret = self.assign(region, offset, v).map(CircuitValue::known);
        });
        ret
    }
}
