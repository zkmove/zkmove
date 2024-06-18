use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::math_gadgets::range_check::IntegerRangeCheck;
use crate::chips::execution_chip_v2::value::Integer;
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use gadgets::util::not;
use halo2_proofs::plonk::Expression;
use types::Field;

#[derive(Clone, Debug)]
pub struct AddGadget<F, const N_BYTES: usize> {
    carry_lo: Cell<F>,
    carry_hi: Cell<F>,
    range_check_out_lo: IntegerRangeCheck<F>,
    range_check_out_hi: Option<IntegerRangeCheck<F>>,
}

impl<F: Field, const N_BYTES: usize> AddGadget<F, N_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        lhs: Integer<F>,
        rhs: Integer<F>,
        out: Integer<F>,
        is_add: Expression<F>, // boolean
    ) -> Self {
        let carry_lo = cb.query_cell();
        let carry_hi = cb.query_cell();

        cb.condition(is_add.clone(), |cb| {
            cb.require_equal(
                "lhs_lo + rhs_lo == out_lo + carry_lo * 2^128",
                lhs.lo() + rhs.lo(),
                out.lo().clone() + carry_lo.expr() * 2u64.pow(128).expr(),
            );
            cb.require_equal(
                "lhs_hi + rhs_hi + carry_lo == out_hi + carry_hi * 2^128",
                lhs.hi() + rhs.hi() + carry_lo.expr(),
                out.hi() + carry_hi.expr() * 2u64.pow(128).expr(),
            );
        });

        cb.condition(not::expr(is_add), |cb| {
            cb.require_equal(
                "out_lo + rhs_lo == lhs_lo + carry_lo * 2^128",
                out.lo().clone() + rhs.lo(),
                lhs.lo() + carry_lo.expr() * 2u64.pow(128).expr(),
            );
            cb.require_equal(
                "out_hi + rhs_hi + carry_lo == lhs_hi + carry_hi * 2^128",
                out.hi() + rhs.hi() + carry_lo.expr(),
                lhs.hi() + carry_hi.expr() * 2u64.pow(128).expr(),
            );
        });

        match N_BYTES {
            NUM_OF_BYTES_U8 | NUM_OF_BYTES_U16 | NUM_OF_BYTES_U32 | NUM_OF_BYTES_U64 => {
                cb.require_zero("carry_lo == 0", carry_lo.expr());
                cb.require_zero("carry_hi == 0", carry_hi.expr());
            }
            NUM_OF_BYTES_U128 => {
                cb.require_in_set(
                    "carry_lo == 0 | 1",
                    carry_lo.expr(),
                    (0u64..2).map(|v| v.expr()).collect(),
                );
                cb.require_zero("carry_hi == 0", carry_hi.expr());
            }
            NUM_OF_BYTES_U256 => {
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
            }
            _ => unreachable!(),
        }

        // range check on the output, no need on the inputs
        let (range_check_out_lo, range_check_out_hi) = match N_BYTES {
            NUM_OF_BYTES_U8 | NUM_OF_BYTES_U16 | NUM_OF_BYTES_U32 | NUM_OF_BYTES_U64 => {
                (IntegerRangeCheck::construct(cb, out.lo(), N_BYTES), None)
            }
            NUM_OF_BYTES_U128 => {
                let range_check_out_lo = IntegerRangeCheck::construct(cb, out.lo(), N_BYTES);
                cb.require_true("out_lo < 2^128", range_check_out_lo.expr());
                // no need to check out_hi, it must be zero.
                (range_check_out_lo, None)
            }
            NUM_OF_BYTES_U256 => {
                // out_lo < 2^128, out_hi < 2^128
                let range_check_out_lo =
                    IntegerRangeCheck::construct(cb, out.lo(), NUM_OF_BYTES_U128);
                cb.require_true("out_lo < 2^128", range_check_out_lo.expr());
                let range_check_out_hi =
                    IntegerRangeCheck::construct(cb, out.hi(), NUM_OF_BYTES_U128);
                cb.require_true("out_hi < 2^128", range_check_out_hi.expr());
                (range_check_out_lo, Some(range_check_out_hi))
            }
            _ => unreachable!(),
        };

        Self {
            carry_lo,
            carry_hi,
            range_check_out_lo,
            range_check_out_hi,
        }
    }

    pub(crate) fn overflow(&self) -> Expression<F> {
        match N_BYTES {
            NUM_OF_BYTES_U8 | NUM_OF_BYTES_U16 | NUM_OF_BYTES_U32 | NUM_OF_BYTES_U64 => {
                1u64.expr() - self.range_check_out_lo.clone().expr() // overflow if output is out of range
            }
            NUM_OF_BYTES_U128 => {
                self.carry_lo.expr() // overflow if carry_lo == 1
            }
            NUM_OF_BYTES_U256 => {
                self.carry_hi.expr() // overflow if carry_hi == 1
            }
            _ => unreachable!(),
        }
    }
}
