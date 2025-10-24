use crate::is_zero::IsZeroGadget;
use crate::lt::LtGadget;
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use circuit_tool::cell_manager::Cell;
use field_exts::Field;
use halo2_proofs::plonk::{ErrorFront as Error, Expression};
use util::sum;

/// Returns (lt, eq):
/// - `lt` is `1` when `lhs < rhs`, `0` otherwise.
/// - `eq` is `1` when `lhs == rhs`, `0` otherwise.
///
/// lhs and rhs `< 256**N_BYTES`
/// `N_BYTES` is required to be `<= MAX_N_BYTES_INTEGER`.
#[derive(Clone, Debug)]
pub struct ComparisonGadget<F, const N_BYTES: usize> {
    lt: LtGadget<F, N_BYTES>,
    eq: IsZeroGadget<F>,
}

impl<F: Field, const N_BYTES: usize> ComparisonGadget<F, N_BYTES> {
    pub fn construct(
        cb: &mut impl ConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        let lt = LtGadget::<F, N_BYTES>::construct(cb, lhs, rhs);
        let eq = IsZeroGadget::<F>::construct(cb, sum::expr(lt.diff_bytes()));

        Self { lt, eq }
    }

    pub fn construct_from_given_bytes(
        cb: &mut impl ConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
        bytes: [Cell<F>; N_BYTES],
    ) -> Self {
        let lt = LtGadget::<F, N_BYTES>::construct_from_given_bytes(cb, lhs, rhs, bytes);
        let eq = IsZeroGadget::<F>::construct(cb, sum::expr(lt.diff_bytes()));

        Self { lt, eq }
    }

    pub fn expr(&self) -> (Expression<F>, Expression<F>) {
        (self.lt.expr(), self.eq.expr())
    }

    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(F, F), Error> {
        // lt
        let (lt, diff) = self.lt.assign(region, offset, lhs, rhs)?;

        // eq
        let eq = self.eq.assign(region, offset, sum::value(&diff))?;

        Ok((lt, eq))
    }
}
