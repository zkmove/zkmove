use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::add::AddGadget;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::range_check::IntegerRangeCheck;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use types::Field;

#[derive(Clone, Debug)]
pub struct AddSub<F> {
    range_check_lo: IntegerRangeCheck<F>,
    range_check_hi: IntegerRangeCheck<F>,
    add: AddGadget<F>,
    is_add: IsZeroGadget<F>,
    is_u8: IsZeroGadget<F>,
    is_u16: IsZeroGadget<F>,
    is_u32: IsZeroGadget<F>,
    is_u64: IsZeroGadget<F>,
    is_u128: IsZeroGadget<F>,
    is_u256: IsZeroGadget<F>,
    overflow: Cell<F>,
}
impl<F: Field> InstructionGadgetV2<F> for AddSub<F> {
    const NAME: &'static str = "AddSub";
    const OPCODES: &'static [Opcode] = &[Opcode::Add, Opcode::Sub];
    const EXECUTION_STATE: ExecutionState = ExecutionState::AddSub;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let range_check_lo = IntegerRangeCheck::construct(cb);
        let range_check_hi = IntegerRangeCheck::construct(cb);
        let add = AddGadget::construct(cb);
        let is_add =
            IsZeroGadget::construct(cb, step_curr.opcode.expr() - (Opcode::Add as u64).expr());
        let is_u8 =
            IsZeroGadget::construct(cb, step_curr.aux0.expr() - (NUM_OF_BYTES_U8 as u64).expr());
        let is_u16 =
            IsZeroGadget::construct(cb, step_curr.aux0.expr() - (NUM_OF_BYTES_U16 as u64).expr());
        let is_u32 =
            IsZeroGadget::construct(cb, step_curr.aux0.expr() - (NUM_OF_BYTES_U32 as u64).expr());
        let is_u64 =
            IsZeroGadget::construct(cb, step_curr.aux0.expr() - (NUM_OF_BYTES_U64 as u64).expr());
        let is_u128 = IsZeroGadget::construct(
            cb,
            step_curr.aux0.expr() - (NUM_OF_BYTES_U128 as u64).expr(),
        );
        let is_u256 = IsZeroGadget::construct(
            cb,
            step_curr.aux0.expr() - (NUM_OF_BYTES_U256 as u64).expr(),
        );
        let overflow = cb.query_bool();

        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in OPCODES",
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
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
            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                step_curr.stack_push_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            // configure add gadget

            let lhs = step_curr.stack_pop_value.as_integer();
            let rhs = step_prev.stack_pop_value.as_integer();
            let out = step_curr.stack_push_value.as_integer();
            add.expr(cb, lhs, rhs, out.clone(), is_add.expr());

            // overflow check

            // U8,U16,U32,U64
            cb.require_zero(
                "out_hi == 0",
                (is_u8.expr() + is_u16.expr() + is_u32.expr() + is_u64.expr()) * out.hi(),
            );
            cb.condition(is_u8.expr(), |cb| {
                let in_range = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U8);
                cb.require_equal(
                    "overflow == !in_range(out_lo)",
                    overflow.expr(),
                    1u64.expr() - in_range,
                );
            });
            cb.condition(is_u16.expr(), |cb| {
                let in_range = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U16);
                cb.require_equal(
                    "overflow == !in_range(out_lo)",
                    overflow.expr(),
                    1u64.expr() - in_range,
                );
            });
            cb.condition(is_u32.expr(), |cb| {
                let in_range = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U32);
                cb.require_equal(
                    "overflow == !in_range(out_lo)",
                    overflow.expr(),
                    1u64.expr() - in_range,
                );
            });
            cb.condition(is_u64.expr(), |cb| {
                let in_range = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U64);
                cb.require_equal(
                    "overflow == !in_range(out_lo)",
                    overflow.expr(),
                    1u64.expr() - in_range,
                );
            });

            // U128
            cb.condition(is_u128.expr(), |cb| {
                let in_range = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U128);
                cb.require_true("out_lo < 2^128", in_range);
                //OVERFLOW if out_hi == 1
                cb.require_in_set(
                    "out_hi == 0 | 1",
                    out.hi(),
                    (0u64..2).map(|v| v.expr()).collect(),
                );
                cb.require_equal("overflow == out_hi", overflow.expr(), out.hi());
            });

            // U256
            cb.condition(is_u256.expr(), |cb| {
                let in_range_lo = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U128);
                let in_range_hi = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U128);
                cb.require_true("out_lo < 2^128", in_range_lo);
                cb.require_true("out_hi < 2^128", in_range_hi);
                cb.require_equal(
                    "overflow == add_gadget.overflow()",
                    overflow.expr(),
                    add.overflow(),
                );
            });

            cb.condition(overflow.expr(), |_cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Delta((-1).expr())),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        AddSub {
            range_check_lo,
            range_check_hi,
            add,
            is_add,
            is_u8,
            is_u16,
            is_u32,
            is_u64,
            is_u128,
            is_u256,
            overflow,
        }
    }
}
