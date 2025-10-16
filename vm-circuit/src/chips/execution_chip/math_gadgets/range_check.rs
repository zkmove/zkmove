use crate::chips::execution_chip::math_gadgets::is_zero::IsZero;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip::utils::{from_bytes, from_limbs};
use crate::chips::execution_chip::value::NUM_OF_BYTES_U128;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use halo2_proofs::{
    circuit::Value,
    plonk::{ErrorFront as Error, Expression},
};
use types::Field;

/// Requires that the passed in value is within the specified range.
/// `N_BYTES` is required to be `<= MAX_N_BYTES_INTEGER`.
#[derive(Clone, Debug)]
pub struct RangeCheckGadget<F, const N_BYTES: usize> {
    parts: [Cell<F>; N_BYTES],
}

impl<F: Field, const N_BYTES: usize> RangeCheckGadget<F, N_BYTES> {
    pub(crate) fn construct(cb: &mut ConstraintBuilderV2<F>, value: Expression<F>) -> Self {
        let parts = cb.query_bytes();

        // Require that the reconstructed value from the parts equals the
        // original value
        cb.require_equal(
            "Constrain bytes recomposited to value",
            value,
            from_limbs::expr::<_, _, 8>(&parts),
        );

        Self { parts }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: F,
    ) -> Result<(), Error> {
        let bytes: [u8; 32] = value.to_repr().as_ref().try_into().unwrap();
        for (idx, part) in self.parts.iter().enumerate() {
            part.assign(region, offset, Value::known(F::from(bytes[idx] as u64)))?;
        }
        Ok(())
    }
}

/// Check if the input value is in the range of U8,U16,U32,U64 or U128
#[derive(Clone, Debug)]
pub struct IntegerRangeCheck<F> {
    bytes: [Cell<F>; NUM_OF_BYTES_U128],
    is_zero: IsZero<F>,
}

impl<F: Field> IntegerRangeCheck<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let bytes = cb.query_bytes();
        let is_zero = IsZero::construct(cb);
        Self { bytes, is_zero }
    }
    pub(crate) fn expr(
        &self,
        cb: &mut ConstraintBuilderV2<F>,
        value: Expression<F>,
        n_bytes: usize,
    ) -> Expression<F> {
        cb.require_equal(
            "the input value is well assigned",
            value.clone(),
            from_bytes::expr(&self.bytes),
        );
        let expected = from_bytes::expr(&self.bytes[..n_bytes]);
        self.is_zero.expr(cb, value - expected)
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: F,
        n_bytes: usize,
    ) -> Result<bool, Error> {
        let bytes: [u8; 32] = value.to_repr().as_ref().try_into().unwrap();
        for (idx, part) in self.bytes.iter().enumerate() {
            part.assign(region, offset, Value::known(F::from(bytes[idx] as u64)))?;
        }
        let expected: F = from_bytes::value(&bytes[..n_bytes]);
        self.is_zero.assign(region, offset, value - expected)
    }
}
