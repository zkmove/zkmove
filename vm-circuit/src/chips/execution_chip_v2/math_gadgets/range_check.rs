use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::utils::{from_bytes, from_limbs};
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use movelang::value::NUM_OF_BYTES_U128;
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
            from_limbs::expr::<_, _, N_BYTES>(&parts),
        );

        Self { parts }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: F,
    ) -> Result<(), Error> {
        let bytes = value.to_repr();
        for (idx, part) in self.parts.iter().enumerate() {
            part.assign(region, offset, Value::known(F::from(bytes[idx] as u64)))?;
        }
        Ok(())
    }
}

/// Check if the input value is in the range of U8,U16,U32,U64 or U128
#[derive(Clone, Debug)]
pub struct IntegerRangeCheck<F, const N_BYTES: usize> {
    bytes: [Cell<F>; NUM_OF_BYTES_U128],
    is_zero: IsZeroGadget<F>,
}

impl<F: Field, const N_BYTES: usize> IntegerRangeCheck<F, N_BYTES> {
    pub(crate) fn construct(cb: &mut ConstraintBuilderV2<F>, value: Expression<F>) -> Self {
        let bytes = cb.query_bytes();

        cb.require_equal(
            "the input value is well assigned",
            value.clone(),
            from_bytes::expr(&bytes),
        );

        let expected_value = from_bytes::expr(&bytes.iter().take(N_BYTES).collect::<Vec<_>>());
        let is_zero = IsZeroGadget::construct(cb, value - expected_value);
        Self { bytes, is_zero }
    }
    pub(crate) fn expr(&self) -> Expression<F> {
        self.is_zero.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: F,
    ) -> Result<(), Error> {
        let bytes = value.to_repr();
        for (idx, part) in self.bytes.iter().enumerate() {
            part.assign(region, offset, Value::known(F::from(bytes[idx] as u64)))?;
        }
        Ok(())
    }
}
