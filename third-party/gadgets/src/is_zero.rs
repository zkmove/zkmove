use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use circuit_tool::cell_manager::Cell;
use field_exts::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{ErrorFront as Error, Expression},
};
use util::Expr;

/// Returns `1` when `value == 0`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsZeroGadget<F> {
    inverse: Cell<F>,
    value: Expression<F>,
    is_zero: Expression<F>,
}

impl<F: Field> IsZeroGadget<F> {
    pub fn construct(cb: &mut impl ConstraintBuilder<F>, value: Expression<F>) -> Self {
        let g = Self::construct_without_configure(cb, value);
        g.configure(cb, "");
        g
    }

    pub fn construct_without_configure(
        cb: &mut impl ConstraintBuilder<F>,
        value: Expression<F>,
    ) -> Self {
        let inverse = cb.query_cell();
        let is_zero = 1u64.expr() - (value.clone() * inverse.expr());
        Self {
            inverse,
            is_zero,
            value,
        }
    }

    pub fn configure(&self, cb: &mut impl ConstraintBuilder<F>, name: impl AsRef<str>) {
        let name = name.as_ref();
        cb.require_zero(
            format!("{}: value * (1 - value * value_inv)", name),
            self.value.clone() * self.is_zero.clone(),
        );
        cb.require_zero(
            format!("{}: value_inv * (1 - value * value_inv)", name),
            self.inverse.expr() * self.is_zero.clone(),
        );
    }
    pub fn expr(&self) -> Expression<F> {
        self.is_zero.clone()
    }

    pub fn assign(
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

/// Returns `1` when `value == 0`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsZero<F> {
    inverse: Cell<F>,
}

impl<F: Field> IsZero<F> {
    pub fn construct(cb: &mut impl ConstraintBuilder<F>) -> Self {
        Self {
            inverse: cb.query_cell(),
        }
    }

    pub fn expr(&self, cb: &mut impl ConstraintBuilder<F>, value: Expression<F>) -> Expression<F> {
        let is_zero = 1u64.expr() - (value.clone() * self.inverse.expr());
        cb.require_zero(
            "value * (1 - value * value_inv)".to_string(),
            value.clone() * is_zero.clone(),
        );
        cb.require_zero(
            "value_inv * (1 - value * value_inv)".to_string(),
            self.inverse.expr() * is_zero.clone(),
        );
        is_zero
    }

    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: F,
    ) -> Result<bool, Error> {
        let inverse = value.invert().unwrap_or(F::ZERO);
        self.inverse.assign(region, offset, Value::known(inverse))?;
        Ok(value.is_zero().into())
    }
}
