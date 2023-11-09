use super::{comparison::ComparisonGadget, lt::LtGadget};
use crate::chips::execution_chip::instructions::common::word_gadget::WordCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::execution_chip::utils::split_u256;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use move_core_types::u256::U256;
use types::Field;

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
/// lhs and rhs are both 256-bit word.
#[derive(Clone, Debug)]
pub struct LtWordGadget<F> {
    comparison_hi: ComparisonGadget<F, 16>,
    lt_lo: LtGadget<F, 16>,
}

impl<F: Field> LtWordGadget<F> {
    #[allow(dead_code)]
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        lhs: &WordCells<F>,
        rhs: &WordCells<F>,
    ) -> Self {
        let comparison_hi =
            ComparisonGadget::construct(cb, lhs.hi.expression.clone(), rhs.hi.expression.clone());
        let lt_lo = LtGadget::construct(cb, lhs.lo.expression.clone(), rhs.lo.expression.clone());
        Self {
            comparison_hi,
            lt_lo,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn expr(&self) -> Expression<F> {
        let (hi_lt, hi_eq) = self.comparison_hi.expr();
        hi_lt + hi_eq * self.lt_lo.expr()
    }

    #[allow(dead_code)]
    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: U256,
        rhs: U256,
    ) -> Result<(), Error> {
        let (lhs_lo, lhs_hi) = split_u256(&lhs);
        let (rhs_lo, rhs_hi) = split_u256(&rhs);
        self.comparison_hi.assign(
            region,
            offset,
            F::from_u128(lhs_hi.unchecked_as_u128()),
            F::from_u128(rhs_hi.unchecked_as_u128()),
        )?;
        self.lt_lo.assign(
            region,
            offset,
            F::from_u128(lhs_lo.unchecked_as_u128()),
            F::from_u128(rhs_lo.unchecked_as_u128()),
        )?;
        Ok(())
    }
}
