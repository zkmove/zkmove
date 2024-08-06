use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::math_gadgets::comparison::ComparisonGadget;
use crate::chips::execution_chip_v2::utils::{from_limbs, transpose_val_ret};
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use gadgets::util::{pow_of_two, Expr};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use move_vm_runtime::witnessing::traced_value::Integer;
use movelang::value::NUM_OF_BYTES_U128;
use types::Field;

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
/// lhs and rhs `< 256**N_BYTES`
/// `N_BYTES` is required to be `<= MAX_N_BYTES_INTEGER` to prevent overflow:
/// values are stored in a single field element and two of these are added
/// together.
/// The equation that is enforced is `lhs - rhs == diff - (lt * range)`.
/// Because all values are `<= 256**N_BYTES` and `lt` is boolean, `lt` can only
/// be `1` when `lhs < rhs`.
#[derive(Clone, Debug)]
pub struct LtGadget<F, const N_BYTES: usize> {
    lt: Cell<F>, // `1` when `lhs < rhs`, `0` otherwise.
    diff: [Cell<F>; N_BYTES], /* The byte values of `diff`.
                  * `diff` equals `lhs - rhs` if `lhs >= rhs`,
                  * `lhs - rhs + range` otherwise. */
    range: F, // The range of the inputs, `256**N_BYTES`
}

impl<F: Field, const N_BYTES: usize> LtGadget<F, N_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        let lt = cb.query_bool();
        let diff = cb.query_bytes();
        let range = pow_of_two(N_BYTES * 8);

        // The equation we require to hold: `lhs - rhs == diff - (lt * range)`.
        cb.require_equal(
            "lhs - rhs == diff - (lt ⋅ range)",
            lhs - rhs,
            from_limbs::expr::<_, _, 8>(&diff) - (lt.expr() * range),
        );

        Self { lt, diff, range }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.lt.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(F, Vec<u8>), Error> {
        // Set `lt`
        let lt = lhs < rhs;
        self.lt.assign(
            region,
            offset,
            Value::known(if lt { F::ONE } else { F::ZERO }),
        )?;

        // Set the bytes of diff
        let diff = (lhs - rhs) + (if lt { self.range } else { F::ZERO });
        let diff_bytes = diff.to_repr();
        for (idx, diff) in self.diff.iter().enumerate() {
            diff.assign(
                region,
                offset,
                Value::known(F::from(diff_bytes[idx] as u64)),
            )?;
        }

        Ok((if lt { F::ONE } else { F::ZERO }, diff_bytes.to_vec()))
    }

    pub(crate) fn diff_bytes(&self) -> Vec<Cell<F>> {
        self.diff.to_vec()
    }

    pub(crate) fn assign_value(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lhs: Value<F>,
        rhs: Value<F>,
    ) -> Result<Value<(F, Vec<u8>)>, Error> {
        transpose_val_ret(
            lhs.zip(rhs)
                .map(|(lhs, rhs)| self.assign(region, offset, lhs, rhs)),
        )
    }
}

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
/// lhs and rhs are both Integer.
#[derive(Clone, Debug)]
pub struct LtInteger<F> {
    comparison_hi: ComparisonGadget<F, NUM_OF_BYTES_U128>,
    lt_lo: LtGadget<F, NUM_OF_BYTES_U128>,
}

impl<F: Field> LtInteger<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        lhs_lo: Expression<F>,
        lhs_hi: Expression<F>,
        rhs_lo: Expression<F>,
        rhs_hi: Expression<F>,
    ) -> Self {
        let comparison_hi = ComparisonGadget::construct(cb, lhs_hi, rhs_hi);
        let lt_lo = LtGadget::construct(cb, lhs_lo, rhs_lo);
        Self {
            comparison_hi,
            lt_lo,
        }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        let (hi_lt, hi_eq) = self.comparison_hi.expr();
        hi_lt + hi_eq * self.lt_lo.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lhs: Integer,
        rhs: Integer,
    ) -> Result<(), Error> {
        let (lhs_lo, lhs_hi) = Integer::try_from(lhs).unwrap().into();
        let (rhs_lo, rhs_hi) = Integer::try_from(rhs).unwrap().into();
        self.comparison_hi
            .assign(region, offset, F::from_u128(lhs_hi), F::from_u128(rhs_hi))?;
        self.lt_lo
            .assign(region, offset, F::from_u128(lhs_lo), F::from_u128(rhs_lo))?;
        Ok(())
    }
}
