use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use circuit_tool::cell_manager::Cell;
use field_exts::util::pow_of_two_expr;
use field_exts::util::Expr;
use field_exts::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{ErrorFront as Error, Expression},
};
use move_core_types::u256::U256;
use value_type::word::IntegerExpr;

#[derive(Clone, Debug)]
pub struct AddGadget<F> {
    carry_lo: Cell<F>,
    carry_hi: Cell<F>,
}

impl<F: Field> AddGadget<F> {
    pub fn construct(cb: &mut impl ConstraintBuilder<F>) -> Self {
        let carry_lo = cb.query_cell();
        let carry_hi = cb.query_cell();

        // we can use query_bool, but the semantics would be a bit fuzzy.
        cb.require_in_set(
            "carry_lo == 0 | 1".to_string(),
            carry_lo.expr(),
            (0u64..2).map(|v| v.expr()).collect(),
        );
        cb.require_in_set(
            "carry_hi == 0 | 1".to_string(),
            carry_hi.expr(),
            (0u64..2).map(|v| v.expr()).collect(),
        );

        Self { carry_lo, carry_hi }
    }

    pub fn expr(
        &self,
        cb: &mut impl ConstraintBuilder<F>,
        lhs: IntegerExpr<F>,
        rhs: IntegerExpr<F>,
        out: IntegerExpr<F>,
    ) {
        cb.require_equal(
            "lhs_lo + rhs_lo == out_lo + carry_lo * 2^128".to_string(),
            lhs.lo() + rhs.lo(),
            out.lo().clone() + self.carry_lo.expr() * pow_of_two_expr(128),
        );
        cb.require_equal(
            "lhs_hi + rhs_hi + carry_lo == out_hi + carry_hi * 2^128".to_string(),
            lhs.hi() + rhs.hi() + self.carry_lo.expr(),
            out.hi() + self.carry_hi.expr() * pow_of_two_expr(128),
        );
    }

    pub fn overflow(&self) -> Expression<F> {
        self.carry_hi.expr() // overflow if carry_hi == 1
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lhs_lo: u128,
        lhs_hi: u128,
        rhs_lo: u128,
        rhs_hi: u128,
        out_lo: u128,
        out_hi: u128,
    ) -> Result<(), Error> {
        let rhs_lo = U256::from(rhs_lo);
        let rhs_hi = U256::from(rhs_hi);
        let lhs_lo = U256::from(lhs_lo);
        let lhs_hi = U256::from(lhs_hi);
        let out_lo = U256::from(out_lo);
        let out_hi = U256::from(out_hi);
        let sum_lo = U256::wrapping_add(lhs_lo, rhs_lo);
        let sum_hi = U256::wrapping_add(lhs_hi, rhs_hi);
        let carry_lo = U256::wrapping_sub(sum_lo, out_lo) >> 128;
        debug_assert!(carry_lo == U256::zero() || carry_lo == U256::one());
        let carry_hi = U256::wrapping_sub(U256::wrapping_add(sum_hi, carry_lo), out_hi) >> 128;
        debug_assert!(carry_hi == U256::zero() || carry_hi == U256::one());
        self.carry_lo.assign(
            region,
            offset,
            Value::known(F::from_u128(carry_lo.unchecked_as_u128())),
        )?;
        self.carry_hi.assign(
            region,
            offset,
            Value::known(F::from_u128(carry_hi.unchecked_as_u128())),
        )?;
        Ok(())
    }
}
