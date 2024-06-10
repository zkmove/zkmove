use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::range_check::IntegerRangeCheck;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use gadgets::util::{and, not};
use types::Field;

#[derive(Clone, Debug)]
pub struct Cast<F, const N_BYTES: usize> {
    in_range_lo: Option<IntegerRangeCheck<F, N_BYTES>>,
    is_zero_hi: Option<IsZeroGadget<F>>,
}
impl<F: Field, const N_BYTES: usize> InstructionGadgetV2<F> for Cast<F, N_BYTES> {
    const NAME: &'static str = match N_BYTES {
        NUM_OF_BYTES_U8 => "CastU8",
        NUM_OF_BYTES_U16 => "CastU16",
        NUM_OF_BYTES_U32 => "CastU32",
        NUM_OF_BYTES_U64 => "CastU64",
        NUM_OF_BYTES_U128 => "CastU128",
        NUM_OF_BYTES_U256 => "CastU256",
        _ => unreachable!(),
    };

    const OPCODE: Opcode = match N_BYTES {
        NUM_OF_BYTES_U8 => Opcode::CastU8,
        NUM_OF_BYTES_U16 => Opcode::CastU16,
        NUM_OF_BYTES_U32 => Opcode::CastU32,
        NUM_OF_BYTES_U64 => Opcode::CastU64,
        NUM_OF_BYTES_U128 => Opcode::CastU128,
        NUM_OF_BYTES_U256 => Opcode::CastU256,
        _ => unreachable!(),
    };
    const EXECUTION_STATE: ExecutionState = match N_BYTES {
        NUM_OF_BYTES_U8 => ExecutionState::CastU8,
        NUM_OF_BYTES_U16 => ExecutionState::CastU16,
        NUM_OF_BYTES_U32 => ExecutionState::CastU32,
        NUM_OF_BYTES_U64 => ExecutionState::CastU64,
        NUM_OF_BYTES_U128 => ExecutionState::CastU128,
        NUM_OF_BYTES_U256 => ExecutionState::CastU256,
        _ => unreachable!(),
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();

        cb.require_equal(
            "opcode",
            step_curr.opcode.expr(),
            (Self::OPCODE as u64).expr(),
        );
        cb.require_equal(
            "step_counter(0) == 1",
            step_curr.step_counter.expr(),
            1u64.expr(),
        );
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
        cb.require_equal(
            format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
            step_curr.stack_push_index.expr(),
            step_curr.sp.expr(),
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

        cb.require_no_local_op();

        let in_range_lo = if N_BYTES != NUM_OF_BYTES_U256 {
            Some(IntegerRangeCheck::<_, N_BYTES>::construct(
                cb,
                step_curr.stack_pop_value.as_integer().lo(),
            ))
        } else {
            None
        };
        let is_zero_hi = if N_BYTES != NUM_OF_BYTES_U256 {
            Some(IsZeroGadget::construct(
                cb,
                step_curr.stack_pop_value.as_integer().hi(),
            ))
        } else {
            None
        };
        let castable = if N_BYTES != NUM_OF_BYTES_U256 {
            and::expr([
                in_range_lo.clone().unwrap().expr(),
                is_zero_hi.clone().unwrap().expr(),
            ])
        } else {
            1u64.expr() // cast u256 will always be in range
        };
        cb.condition(castable.clone(), |cb| {
            cb.require_equal(
                format!("{}, stack_push_value(0) == stack_pop_value(0)", Self::NAME),
                step_curr.stack_push_value.expr(),
                step_curr.stack_pop_value.expr(),
            );
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });
        cb.condition(not::expr(castable), |cb| {
            // TODO: error state
            // cb.require_next_state(ExecutionState::ErrorState);
            // ErrorCode == StatusCode::ArithmeticError
        });

        Cast {
            in_range_lo,
            is_zero_hi,
        }
    }
}
