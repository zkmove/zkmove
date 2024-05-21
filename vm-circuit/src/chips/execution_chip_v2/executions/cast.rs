use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::range_check::IntegerRangeCheck;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use gadgets::util::not;
use types::Field;

#[derive(Clone, Debug)]
pub struct Cast<F, const N_BYTES: usize> {
    range_check: IntegerRangeCheck<F, N_BYTES>,
}
impl<F: Field, const N_BYTES: usize> InstructionGadgetV2<F> for Cast<F, N_BYTES> {
    const NAME: &'static str = match N_BYTES {
        8 => "CastU8",
        16 => "CastU16",
        32 => "CastU32",
        64 => "CastU64",
        128 => "CastU128",
        _ => unreachable!(),
    };

    const OPCODE: Opcode = match N_BYTES {
        8 => Opcode::CastU8,
        16 => Opcode::CastU16,
        32 => Opcode::CastU32,
        64 => Opcode::CastU64,
        128 => Opcode::CastU128,
        _ => unreachable!(),
    };
    const EXECUTION_STATE: ExecutionState = match N_BYTES {
        8 => ExecutionState::CastU8,
        16 => ExecutionState::CastU16,
        32 => ExecutionState::CastU32,
        64 => ExecutionState::CastU64,
        128 => ExecutionState::CastU128,
        _ => unreachable!(),
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let range_check =
            IntegerRangeCheck::<_, N_BYTES>::construct(cb, cb.curr.state.stack_pop_value.expr());
        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                cb.curr.state.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
                cb.curr.state.stack_pop_index.expr(),
                cb.curr.state.sp.expr(),
            );
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                cb.curr.state.stack_pop_sub_index.expr(),
            );
            cb.require_zero(
                format!("{}, stack_pop_value_header(0) == false", Self::NAME),
                cb.curr.state.stack_pop_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
                cb.curr.state.stack_push_index.expr(),
                cb.curr.state.sp.expr(),
            );

            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                cb.curr.state.stack_push_sub_index.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                cb.curr.state.stack_push_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                cb.curr.state.stack_push_version.expr(),
                cb.curr.state.clk.expr(),
            );

            cb.require_no_local_op();

            cb.condition(range_check.expr(), |cb| {
                cb.require_equal(
                    format!("{}, stack_push_value(0) == stack_pop_value(0)", Self::NAME),
                    cb.curr.state.stack_push_value.expr(),
                    cb.curr.state.stack_pop_value.expr(),
                );
                cb.require_state_transition(vec![
                    (FRAME_INDEX, Transition::Same),
                    (MODULE_INDEX, Transition::Same),
                    (FUNCTION_INDEX, Transition::Same),
                    (SP, Transition::Same),
                    (PC, Transition::Delta(1.expr())),
                ]);
            });
            cb.condition(not::expr(range_check.expr()), |cb| {
                // TODO: error state
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });
        });

        Cast { range_check }
    }
}
