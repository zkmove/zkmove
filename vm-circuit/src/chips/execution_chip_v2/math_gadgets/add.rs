use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::range_check::IntegerRangeCheck;
use crate::chips::execution_chip_v2::value::Integer;
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use gadgets::util::or;
use halo2_proofs::plonk::Expression;
use types::Field;

#[derive(Clone, Debug)]
pub struct AddGadget<F> {
    carry_lo: Cell<F>,
    carry_hi: Cell<F>,
    n_bytes_1: IsZeroGadget<F>,
    n_bytes_2: IsZeroGadget<F>,
    n_bytes_4: IsZeroGadget<F>,
    n_bytes_8: IsZeroGadget<F>,
    n_bytes_16: IsZeroGadget<F>,
    n_bytes_32: IsZeroGadget<F>,
}

impl<F: Field> AddGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        lhs: Integer<F>,
        rhs: Integer<F>,
        out: Integer<F>,
        n_bytes: Expression<F>,
    ) -> Self {
        let carry_lo = cb.query_cell();
        let carry_hi = cb.query_cell();
        let n_bytes_1 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U8 as u64).expr());
        let n_bytes_2 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U16 as u64).expr());
        let n_bytes_4 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U32 as u64).expr());
        let n_bytes_8 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U64 as u64).expr());
        let n_bytes_16 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U128 as u64).expr());
        let n_bytes_32 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U256 as u64).expr());

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

        // range check on the output, no need on the inputs
        // overflow check
        cb.condition(
            or::expr([
                n_bytes_1.expr(),
                n_bytes_2.expr(),
                n_bytes_4.expr(),
                n_bytes_8.expr(),
            ]),
            |cb| {
                cb.require_zero("carry_lo == 0", carry_lo.expr());
                cb.require_zero("carry_hi == 0", carry_hi.expr());
            },
        );
        cb.condition(n_bytes_1.expr(), |cb| {
            let out_lo_in_range = IntegerRangeCheck::<_, NUM_OF_BYTES_U8>::construct(cb, out.lo());
            cb.condition(1u64.expr() - out_lo_in_range.expr(), |cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });
        });
        cb.condition(n_bytes_2.expr(), |cb| {
            let out_lo_in_range = IntegerRangeCheck::<_, NUM_OF_BYTES_U16>::construct(cb, out.lo());
            cb.condition(1u64.expr() - out_lo_in_range.expr(), |cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });
        });
        cb.condition(n_bytes_4.expr(), |cb| {
            let out_lo_in_range = IntegerRangeCheck::<_, NUM_OF_BYTES_U32>::construct(cb, out.lo());
            cb.condition(1u64.expr() - out_lo_in_range.expr(), |cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });
        });
        cb.condition(n_bytes_8.expr(), |cb| {
            let out_lo_in_range = IntegerRangeCheck::<_, NUM_OF_BYTES_U64>::construct(cb, out.lo());
            cb.condition(1u64.expr() - out_lo_in_range.expr(), |cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });
        });
        cb.condition(n_bytes_16.expr(), |cb| {
            let out_lo_in_range =
                IntegerRangeCheck::<_, NUM_OF_BYTES_U128>::construct(cb, out.lo());
            cb.require_true("out_lo < 2^128", out_lo_in_range.expr());
            cb.require_in_set(
                "carry_lo == 0 | 1",
                carry_lo.expr(),
                (0u64..2).map(|v| v.expr()).collect(),
            );
            cb.require_zero("carry_hi == 0", carry_hi.expr());

            // if carry_lo == 1, overflow
            cb.condition(carry_lo.expr(), |cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });
        });
        cb.condition(n_bytes_32.expr(), |cb| {
            // out_lo < 2^128, out_hi < 2^128
            let range_check_out_lo =
                IntegerRangeCheck::<_, NUM_OF_BYTES_U128>::construct(cb, out.lo());
            cb.require_true("out_lo < 2^128", range_check_out_lo.expr());
            let range_check_out_hi =
                IntegerRangeCheck::<_, NUM_OF_BYTES_U128>::construct(cb, out.hi());
            cb.require_true("out_hi < 2^128", range_check_out_hi.expr());
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
            // if carry_hi == 1, overflow
            cb.condition(carry_hi.expr(), |cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });
        });

        Self {
            carry_lo,
            carry_hi,
            n_bytes_1,
            n_bytes_2,
            n_bytes_4,
            n_bytes_8,
            n_bytes_16,
            n_bytes_32,
        }
    }
}
