use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZero;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::lt::LtGadget;
use crate::chips::execution_chip_v2::math_gadgets::mul_add::MulAddExprs;
use crate::chips::execution_chip_v2::math_gadgets::mul_add::MulAddGadget;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::utils::{from_bytes, from_limbs};
use crate::chips::execution_chip_v2::value::Integer;
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use gadgets::util::{and, or, select};
use halo2_proofs::plonk::Expression;
use itertools::izip;
use types::Field;

#[derive(Clone, Debug)]
struct MulDivModCells<F> {
    a_lo: [Cell<F>; NUM_OF_BYTES_U128],
    a_hi: [Cell<F>; NUM_OF_BYTES_U128],
    b_lo: [Cell<F>; NUM_OF_BYTES_U128],
    b_hi: [Cell<F>; NUM_OF_BYTES_U128],
    c_lo: [Cell<F>; NUM_OF_BYTES_U128],
    c_hi: [Cell<F>; NUM_OF_BYTES_U128],
    d_lo: [Cell<F>; NUM_OF_BYTES_U128],
    d_hi: [Cell<F>; NUM_OF_BYTES_U128],
}

#[derive(Clone, Debug)]
pub struct MulDivMod<F> {
    bytes_1_lo: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_1_hi: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_2_lo: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_2_hi: [Cell<F>; NUM_OF_BYTES_U128],
    is_mul: IsZeroGadget<F>,
    is_div: IsZeroGadget<F>,
    is_mod: IsZeroGadget<F>,
    mul_div_mod: Option<MulDivModGadget<F>>,
}
impl<F: Field> InstructionGadgetV2<F> for MulDivMod<F> {
    const NAME: &'static str = "Mul_Div_Mod";
    const OPCODE: Opcode = Opcode::Mul; //TODO: remove this
    const EXECUTION_STATE: ExecutionState = ExecutionState::MulDivMod;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let bytes_1_lo = cb.query_bytes();
        let bytes_1_hi = cb.query_bytes();
        let bytes_2_lo = cb.query_bytes();
        let bytes_2_hi = cb.query_bytes();
        let is_mul =
            IsZeroGadget::construct(cb, (Opcode::Mul as u64).expr() - step_curr.opcode.expr());
        let is_div =
            IsZeroGadget::construct(cb, (Opcode::Div as u64).expr() - step_curr.opcode.expr());
        let is_mod =
            IsZeroGadget::construct(cb, (Opcode::Mod as u64).expr() - step_curr.opcode.expr());
        let mut mul_div_mod = None;

        cb.first_row(|cb| {
            cb.require_equal(
                "step_counter(0) == 2",
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
        });

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_value_header(0) == false", Self::NAME),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_no_local_op();

        cb.last_row(|cb| {
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );

            let lhs = step_curr.stack_pop_value.as_integer();
            let rhs = step_prev.stack_pop_value.as_integer();
            let out = step_curr.stack_push_value.as_integer();
            let cells = MulDivModCells {
                a_lo: bytes_1_lo.clone(),
                a_hi: bytes_1_hi.clone(),
                b_lo: bytes_2_lo.clone(),
                b_hi: bytes_2_hi.clone(),
                c_lo: cb.cells_at_offset(bytes_1_lo.clone(), -1),
                c_hi: cb.cells_at_offset(bytes_1_hi.clone(), -1),
                d_lo: cb.cells_at_offset(bytes_2_lo.clone(), -1),
                d_hi: cb.cells_at_offset(bytes_2_hi.clone(), -1),
            };

            mul_div_mod = Some(MulDivModGadget::construct(
                cb,
                cells,
                lhs,
                rhs,
                out,
                is_mul.expr(),
                is_div.expr(),
                is_mod.expr(),
                step_curr.aux0.expr(), //n_bytes
            ));

            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                step_curr.stack_push_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        MulDivMod {
            bytes_1_lo,
            bytes_1_hi,
            bytes_2_lo,
            bytes_2_hi,
            is_mul,
            is_div,
            is_mod,
            mul_div_mod,
        }
    }
}

#[derive(Clone, Debug)]
struct MulDivModGadget<F> {
    cells: MulDivModCells<F>,
    mul_add: MulAddGadget<F>,
    divisor_is_zero: IsZeroGadget<F>,
    remainder_lt_divisor: LtGadget<F, NUM_OF_BYTES_U256>,
    overflow_general: IsZeroGadget<F>,
    overflow: Cell<F>,
    is_u8: IsZeroGadget<F>,
    is_u16: IsZeroGadget<F>,
    is_u32: IsZeroGadget<F>,
    is_u64: IsZeroGadget<F>,
    is_u128: IsZeroGadget<F>,
    is_out_lo_in_range: IsZero<F>,
    is_zero_out_hi: IsZero<F>,
}

impl<F: Field> MulDivModGadget<F> {
    fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        cells: MulDivModCells<F>,
        lhs: Integer<F>,
        rhs: Integer<F>,
        out: Integer<F>,
        is_mul: Expression<F>,
        is_div: Expression<F>,
        is_mod: Expression<F>,
        n_bytes: Expression<F>,
    ) -> Self {
        let a_limbs = [
            from_bytes::expr(&cells.a_lo[..NUM_OF_BYTES_U64]),
            from_bytes::expr(&cells.a_lo[NUM_OF_BYTES_U64..]),
            from_bytes::expr(&cells.a_hi[..NUM_OF_BYTES_U64]),
            from_bytes::expr(&cells.a_hi[NUM_OF_BYTES_U64..]),
        ];
        let b_limbs = [
            from_bytes::expr(&cells.b_lo[..NUM_OF_BYTES_U64]),
            from_bytes::expr(&cells.b_lo[NUM_OF_BYTES_U64..]),
            from_bytes::expr(&cells.b_hi[..NUM_OF_BYTES_U64]),
            from_bytes::expr(&cells.b_hi[NUM_OF_BYTES_U64..]),
        ];
        let a = from_limbs::expr::<_, _, 64>(&a_limbs);
        let b = from_limbs::expr::<_, _, 64>(&b_limbs);

        let c_lo = from_bytes::expr(&cells.c_lo);
        let c_hi = from_bytes::expr(&cells.c_hi);
        let d_lo = from_bytes::expr(&cells.d_lo);
        let d_hi = from_bytes::expr(&cells.d_hi);
        let c = c_hi.clone() * 2u64.pow(128).expr() + c_lo.clone();
        let d = d_hi.clone() * 2u64.pow(128).expr() + d_lo.clone();

        // Connect "lhs,rhs,out" with "a,b,c,d":
        //
        // lhs == select::expr(is_mul.expr(), a, d);
        // rhs == b;
        // out == is_mul.clone() * d.expr()
        //     + is_div.clone() * a.expr() * (1.expr() - divisor_is_zero.expr())
        //     + is_mod.clone() * c.expr() * (1.expr() - divisor_is_zero.expr());

        //FIXME(?): when is_mod is true and divide by zero, out should be c, but not 0
        cb.require_equal(
            "lhs == select::expr(is_mul.expr(), a, d)",
            lhs.expr(),
            select::expr(is_mul.expr(), a.clone(), d.clone()),
        );
        cb.require_equal("rhs == b", rhs.expr(), b.clone());
        let divisor_is_zero = IsZeroGadget::construct(cb, b.clone());
        cb.require_equal(
            "constrain out",
            out.expr(),
            is_mul.expr() * d
                + is_div.expr() * a * (1u64.expr() - divisor_is_zero.expr())
                + is_mod.expr() * c.clone() * (1u64.expr() - divisor_is_zero.expr()),
        );

        // Constraints for a, b, c, d:
        //
        // for Mul, c must be 0
        // for Div&Mod, remainder(c) < divisor(b) when divisor != 0
        // for Div&Mod, go to Error state if divisor == 0
        cb.require_zero("c == 0 for Mul", c.clone() * is_mul.clone());
        let remainder_lt_divisor = LtGadget::construct(cb, c.clone(), b.clone());
        cb.require_true(
            "remainder < divisor when divisor != 0",
            remainder_lt_divisor.expr()
                * (1.expr() - divisor_is_zero.expr())
                * (1.expr() - is_mul.expr()),
        );
        cb.condition(
            and::expr([1.expr() - is_mul.expr(), divisor_is_zero.expr()]),
            |cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            },
        );

        // Construct MulAddGadget

        let mul_add_exprs = MulAddExprs {
            a_limbs,
            b_limbs,
            c_hi,
            c_lo,
            d_hi,
            d_lo,
        };
        let mul_add = MulAddGadget::construct(cb, &mul_add_exprs);

        // Handle overflow
        //
        // 1.general overflow check for MulAddGadget.
        // 2.overflow check on the output according to the operand type. We don't need check
        // U256, it's already covered by general overflow check

        let overflow_general = IsZeroGadget::construct(cb, mul_add.overflow());
        cb.condition(1u64.expr() - overflow_general.expr(), |_cb| {
            // cb.require_next_state(ExecutionState::ErrorState);
            // ErrorCode == StatusCode::ArithmeticError
        });

        let is_u8 = IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U8 as u64).expr());
        let is_u16 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U16 as u64).expr());
        let is_u32 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U32 as u64).expr());
        let is_u64 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U64 as u64).expr());
        let is_u128 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U128 as u64).expr());
        let is_out_lo_in_range = IsZero::construct(cb);
        let out_lo_bytes = izip!(&cells.d_lo, &cells.a_lo, &cells.c_lo)
            .map(|(c1, c2, c3)| {
                is_mul.expr() * c1.expr() + is_div.expr() * c2.expr() + is_mod.expr() * c3.expr()
            })
            .collect::<Vec<_>>();
        let overflow = cb.query_bool();

        cb.condition(is_u8.expr(), |cb| {
            let in_range = is_out_lo_in_range.expr(
                cb,
                out.lo() - from_bytes::expr(&out_lo_bytes[..NUM_OF_BYTES_U8]),
            );
            cb.require_equal(
                "overflow == !in_range(out_lo)",
                overflow.expr(),
                1u64.expr() - in_range,
            );
        });
        cb.condition(is_u16.expr(), |cb| {
            let in_range = is_out_lo_in_range.expr(
                cb,
                out.lo() - from_bytes::expr(&out_lo_bytes[..NUM_OF_BYTES_U16]),
            );
            cb.require_equal(
                "overflow == !in_range(out_lo)",
                overflow.expr(),
                1u64.expr() - in_range,
            );
        });
        cb.condition(is_u32.expr(), |cb| {
            let in_range = is_out_lo_in_range.expr(
                cb,
                out.lo() - from_bytes::expr(&out_lo_bytes[..NUM_OF_BYTES_U32]),
            );
            cb.require_equal(
                "overflow == !in_range(out_lo)",
                overflow.expr(),
                1u64.expr() - in_range,
            );
        });
        cb.condition(is_u64.expr(), |cb| {
            let in_range = is_out_lo_in_range.expr(
                cb,
                out.lo() - from_bytes::expr(&out_lo_bytes[..NUM_OF_BYTES_U64]),
            );
            cb.require_equal(
                "overflow == !in_range(out_lo)",
                overflow.expr(),
                1u64.expr() - in_range,
            );
        });
        cb.condition(is_u128.expr(), |cb| {
            let in_range = is_out_lo_in_range.expr(cb, out.lo() - from_bytes::expr(&out_lo_bytes));
            cb.require_equal(
                "overflow == !in_range(out_lo)",
                overflow.expr(),
                1u64.expr() - in_range,
            );
        });

        let is_zero_out_hi = IsZero::construct(cb);
        let is_zero_out_hi_expr = is_zero_out_hi.expr(cb, out.hi());
        cb.condition(
            or::expr([overflow.expr(), 1u64.expr() - is_zero_out_hi_expr]),
            |_cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            },
        );

        MulDivModGadget {
            cells,
            mul_add,
            divisor_is_zero,
            remainder_lt_divisor,
            overflow_general,
            overflow,
            is_u8,
            is_u16,
            is_u32,
            is_u64,
            is_u128,
            is_out_lo_in_range,
            is_zero_out_hi,
        }
    }
}
