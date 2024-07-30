use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::lookup_table::Lookup;
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
use gadgets::util::select;
use halo2_proofs::plonk::Expression;
use types::Field;

#[derive(Clone, Debug)]
struct ShiftCells<F> {
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
pub struct Shift<F> {
    bytes_1_lo: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_1_hi: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_2_lo: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_2_hi: [Cell<F>; NUM_OF_BYTES_U128],
    is_shl: IsZeroGadget<F>,
    shift_gadget: Option<ShiftGadget<F>>,
    rhs_lt256: Option<LtGadget<F, NUM_OF_BYTES_U8>>,
    rhs_lt128: Option<LtGadget<F, NUM_OF_BYTES_U8>>,
    rhs_lt64: Option<LtGadget<F, NUM_OF_BYTES_U8>>,
    rhs_lt32: Option<LtGadget<F, NUM_OF_BYTES_U8>>,
    rhs_lt16: Option<LtGadget<F, NUM_OF_BYTES_U8>>,
    rhs_lt8: Option<LtGadget<F, NUM_OF_BYTES_U8>>,
    is_u8: IsZeroGadget<F>,
    is_u16: IsZeroGadget<F>,
    is_u32: IsZeroGadget<F>,
    is_u64: IsZeroGadget<F>,
    is_u128: IsZeroGadget<F>,
    is_u256: IsZeroGadget<F>,
}
impl<F: Field> InstructionGadgetV2<F> for Shift<F> {
    const NAME: &'static str = "Shift";
    const OPCODE: Opcode = Opcode::Shl; //TODO: remove this
    const EXECUTION_STATE: ExecutionState = ExecutionState::Shift;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let bytes_1_lo = cb.query_bytes();
        let bytes_1_hi = cb.query_bytes();
        let bytes_2_lo = cb.query_bytes();
        let bytes_2_hi = cb.query_bytes();
        let is_shl =
            IsZeroGadget::construct(cb, (Opcode::Shl as u64).expr() - step_curr.opcode.expr());
        let mut shift_gadget = None;
        let mut rhs_lt256 = None;
        let mut rhs_lt128 = None;
        let mut rhs_lt64 = None;
        let mut rhs_lt32 = None;
        let mut rhs_lt16 = None;
        let mut rhs_lt8 = None;

        let n_bytes = step_curr.aux0.expr();
        let is_u8 = IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U8 as u64).expr());
        let is_u16 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U16 as u64).expr());
        let is_u32 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U32 as u64).expr());
        let is_u64 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U64 as u64).expr());
        let is_u128 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U128 as u64).expr());
        let is_u256 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U256 as u64).expr());
        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in [Shl, Shr]",
                step_curr.opcode.expr(),
                vec![(Opcode::Shl as u64).expr(), (Opcode::Shr as u64).expr()],
            );
            cb.require_equal(
                "step_counter(0) == 2",
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr(),
            );
            //keep sp unchanged to make assign easier
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

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
                format!("{}, stack_pop_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );

            let lhs = step_curr.stack_pop_value.as_integer();
            let rhs = step_prev.stack_pop_value.as_integer();
            let out = step_curr.stack_push_value.as_integer();

            let rhs_lt_256 = LtGadget::construct(cb, rhs.expr(), 256u64.expr());
            let rhs_lt_128 = LtGadget::construct(cb, rhs.expr(), 128u64.expr());
            let rhs_lt_64 = LtGadget::construct(cb, rhs.expr(), 64u64.expr());
            let rhs_lt_32 = LtGadget::construct(cb, rhs.expr(), 32u64.expr());
            let rhs_lt_16 = LtGadget::construct(cb, rhs.expr(), 16u64.expr());
            let rhs_lt_8 = LtGadget::construct(cb, rhs.expr(), 8u64.expr());

            // Opcode Shl and Shr shifts the "lhs" integer "rhs" bits and pushes the "out" on the stack.
            // lhs and out can be U8, U16, U32, U64, U128 or U256
            // rhs can only be U8
            cb.require_true(format!("{}, rhs < 256", Self::NAME), rhs_lt_256.expr());

            // According to VM implementation, if lhs has integer type UX, rhs must be less then N_BITS_UX,
            // otherwise goto Error
            let error = is_u8.expr() * (1u64.expr() - rhs_lt_8.expr())
                + is_u16.expr() * (1u64.expr() - rhs_lt_16.expr())
                + is_u32.expr() * (1u64.expr() - rhs_lt_32.expr())
                + is_u64.expr() * (1u64.expr() - rhs_lt_64.expr())
                + is_u128.expr() * (1u64.expr() - rhs_lt_128.expr());
            cb.condition(error, |_cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });
            rhs_lt256 = Some(rhs_lt_256);
            rhs_lt128 = Some(rhs_lt_128);
            rhs_lt64 = Some(rhs_lt_64);
            rhs_lt32 = Some(rhs_lt_32);
            rhs_lt16 = Some(rhs_lt_16);
            rhs_lt8 = Some(rhs_lt_8);

            let cells = ShiftCells {
                a_lo: bytes_1_lo.clone(),
                a_hi: bytes_1_hi.clone(),
                b_lo: bytes_2_lo.clone(),
                b_hi: bytes_2_hi.clone(),
                c_lo: cb.cells_at_offset(bytes_1_lo.clone(), -1),
                c_hi: cb.cells_at_offset(bytes_1_hi.clone(), -1),
                d_lo: cb.cells_at_offset(bytes_2_lo.clone(), -1),
                d_hi: cb.cells_at_offset(bytes_2_hi.clone(), -1),
            };

            shift_gadget = Some(ShiftGadget::construct(
                cb,
                cells,
                lhs,
                rhs,
                out,
                is_shl.expr(),
                is_u8.expr(),
                is_u16.expr(),
                is_u32.expr(),
                is_u64.expr(),
                is_u128.expr(),
                is_u256.expr(),
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
                (SP, Transition::Delta((-1).expr())),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        Shift {
            bytes_1_lo,
            bytes_1_hi,
            bytes_2_lo,
            bytes_2_hi,
            is_shl,
            shift_gadget,
            rhs_lt256,
            rhs_lt128,
            rhs_lt64,
            rhs_lt32,
            rhs_lt16,
            rhs_lt8,
            is_u8,
            is_u16,
            is_u32,
            is_u64,
            is_u128,
            is_u256,
        }
    }
}

#[derive(Clone, Debug)]
struct ShiftGadget<F> {
    cells: ShiftCells<F>,
    mul_add: MulAddGadget<F>,
    remainder_lt_divisor: LtGadget<F, NUM_OF_BYTES_U256>,
}

impl<F: Field> ShiftGadget<F> {
    fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        cells: ShiftCells<F>,
        lhs: Integer<F>,
        rhs: Integer<F>,
        out: Integer<F>,
        is_shl: Expression<F>,
        is_u8: Expression<F>,
        is_u16: Expression<F>,
        is_u32: Expression<F>,
        is_u64: Expression<F>,
        is_u128: Expression<F>,
        is_u256: Expression<F>,
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

        let b_lo = from_bytes::expr(&cells.b_lo);
        let b_hi = from_bytes::expr(&cells.b_hi);

        let c_lo = from_bytes::expr(&cells.c_lo);
        let c_hi = from_bytes::expr(&cells.c_hi);
        let d_lo = from_bytes::expr(&cells.d_lo);
        let d_hi = from_bytes::expr(&cells.d_hi);
        let c = c_hi.clone() * 2u64.pow(128).expr() + c_lo.clone();
        let d = d_hi.clone() * 2u64.pow(128).expr() + d_lo.clone();

        /// Connect "lhs,rhs,out" with "a,b,c,d":
        ///
        /// lhs == select(is_shl, a, d);
        /// 2^rhs == b; (b != 0, because rhs < 256)
        /// out == is_shl * from_bytes(d[..n_bytes]) + is_shr * a;
        ///
        let is_shr = 1u64.expr() - is_shl.expr();
        cb.require_equal(
            "lhs == select::expr(is_shl.expr(), a, d)",
            lhs.expr(),
            select::expr(is_shl.expr(), a.clone(), d.clone()),
        );
        // (b_lo, b_hi) == (2^rhs, 0), when rhs < 128
        // (b_lo, b_hi) == (0, 2^(rhs - 128)), when rhs >= 128
        cb.add_lookup(
            "2^rhs == b",
            Lookup::Pow2 {
                value: rhs.expr(),
                pow_lo: b_lo,
                pow_hi: b_hi,
            },
        );
        cb.require_equal(
            "constrain out shl",
            out.expr(),
            is_shr.clone() * a
                + is_shl.clone() * is_u8 * from_bytes::expr(&cells.d_lo[..NUM_OF_BYTES_U8])
                + is_shl.clone() * is_u16 * from_bytes::expr(&cells.d_lo[..NUM_OF_BYTES_U16])
                + is_shl.clone() * is_u32 * from_bytes::expr(&cells.d_lo[..NUM_OF_BYTES_U32])
                + is_shl.clone() * is_u64 * from_bytes::expr(&cells.d_lo[..NUM_OF_BYTES_U64])
                + is_shl.clone() * is_u128 * d_lo.clone()
                + is_shl.clone() * is_u256 * d,
        );

        /// Constraints for a, b, c, d:
        ///
        /// for shl, c must be 0, mul_add could overflow, it doesn't impact shift result
        /// for shr, c < b (remainder < divisor, shl also applicable), mul_add never overflow
        ///
        cb.require_zero("c == 0 for shl", c.clone() * is_shl.clone());
        let remainder_lt_divisor = LtGadget::construct(cb, c.clone(), b.clone());
        cb.require_true("remainder < divisor", remainder_lt_divisor.expr());
        let mul_add_exprs = MulAddExprs {
            a_limbs,
            b_limbs,
            c_hi,
            c_lo,
            d_hi,
            d_lo,
        };
        let mul_add = MulAddGadget::construct(cb, &mul_add_exprs);
        cb.require_zero(
            "overflow == 0 for opcode shr",
            is_shr.clone() * mul_add.overflow(),
        );

        ShiftGadget {
            cells,
            mul_add,
            remainder_lt_divisor,
        }
    }
}
