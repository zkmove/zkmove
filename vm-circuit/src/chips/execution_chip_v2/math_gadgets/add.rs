use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::value::Integer;
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use gadgets::util::not;
use halo2_proofs::plonk::Expression;
use types::Field;

#[derive(Clone, Debug)]
pub struct AddGadget<F> {
    carry_lo: Cell<F>,
    carry_hi: Cell<F>,
}

impl<F: Field> AddGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let carry_lo = cb.query_cell();
        let carry_hi = cb.query_cell();

        // we can use query_bool, but the semantics would be a bit fuzzy.
        cb.require_in_set(
            "carry_lo == 0 | 1",
            carry_lo.expr(),
            (0u64..2).map(|v| v.expr()).collect(),
        );
        cb.require_in_set(
            "carry_hi == 0 | 1",
            carry_hi.expr(),
            (0u64..2).map(|v| v.expr()).collect(),
        );

        Self { carry_lo, carry_hi }
    }

    pub(crate) fn expr(
        &self,
        cb: &mut ConstraintBuilderV2<F>,
        lhs: Integer<F>,
        rhs: Integer<F>,
        out: Integer<F>,
        is_add: Expression<F>, // boolean
    ) {
        cb.condition(is_add.clone(), |cb| {
            cb.require_equal(
                "lhs_lo + rhs_lo == out_lo + carry_lo * 2^128",
                lhs.lo() + rhs.lo(),
                out.lo().clone() + self.carry_lo.expr() * 2u64.pow(128).expr(),
            );
            cb.require_equal(
                "lhs_hi + rhs_hi + carry_lo == out_hi + carry_hi * 2^128",
                lhs.hi() + rhs.hi() + self.carry_lo.expr(),
                out.hi() + self.carry_hi.expr() * 2u64.pow(128).expr(),
            );
        });

        cb.condition(not::expr(is_add), |cb| {
            cb.require_equal(
                "out_lo + rhs_lo == lhs_lo + carry_lo * 2^128",
                out.lo().clone() + rhs.lo(),
                lhs.lo() + self.carry_lo.expr() * 2u64.pow(128).expr(),
            );
            cb.require_equal(
                "out_hi + rhs_hi + carry_lo == lhs_hi + carry_hi * 2^128",
                out.hi() + rhs.hi() + self.carry_lo.expr(),
                lhs.hi() + self.carry_hi.expr() * 2u64.pow(128).expr(),
            );
        });
    }

    pub(crate) fn overflow(&self) -> Expression<F> {
        self.carry_hi.expr() // overflow if carry_hi == 1
    }
}
