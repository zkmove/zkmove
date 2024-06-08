use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::range_check::RangeCheckGadget;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct Ld<F, const N_BYTES: usize> {
    phantom_data: PhantomData<F>,
}
impl<F: Field, const N_BYTES: usize> InstructionGadgetV2<F> for Ld<F, N_BYTES> {
    const NAME: &'static str = match N_BYTES {
        NUM_OF_BYTES_U8 => "LdU8",
        NUM_OF_BYTES_U16 => "LdU16",
        NUM_OF_BYTES_U32 => "LdU32",
        NUM_OF_BYTES_U64 => "LdU64",
        NUM_OF_BYTES_U128 => "LdU128",
        NUM_OF_BYTES_U256 => "LdU256",
        _ => unreachable!(),
    };

    const OPCODE: Opcode = match N_BYTES {
        NUM_OF_BYTES_U8 => Opcode::LdU8,
        NUM_OF_BYTES_U16 => Opcode::LdU16,
        NUM_OF_BYTES_U32 => Opcode::LdU32,
        NUM_OF_BYTES_U64 => Opcode::LdU64,
        NUM_OF_BYTES_U128 => Opcode::LdU128,
        NUM_OF_BYTES_U256 => Opcode::LdU256,
        _ => unreachable!(),
    };
    const EXECUTION_STATE: ExecutionState = match N_BYTES {
        NUM_OF_BYTES_U8 => ExecutionState::LdU8,
        NUM_OF_BYTES_U16 => ExecutionState::LdU16,
        NUM_OF_BYTES_U32 => ExecutionState::LdU32,
        NUM_OF_BYTES_U64 => ExecutionState::LdU64,
        NUM_OF_BYTES_U128 => ExecutionState::LdU128,
        NUM_OF_BYTES_U256 => ExecutionState::LdU256,
        _ => unreachable!(),
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.require_equal(
            "opcode",
            cb.curr.state.opcode.expr(),
            (Self::OPCODE as u64).expr(),
        );

        cb.require_equal(
            "step_counter(0) == 1",
            cb.curr.state.step_counter.expr(),
            1u64.expr(),
        );

        cb.require_equal(
            format!("{}, stack_push_index(0) == sp(0) + 1", Self::NAME),
            cb.curr.state.stack_push_index.expr(),
            cb.curr.state.sp.expr() + 1u64.expr(),
        );

        cb.require_zero(
            format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
            cb.curr.state.stack_push_sub_index.expr(),
        );

        cb.require_equal(
            format!("{}, stack_push_value(0).lo == aux0(0)", Self::NAME),
            cb.curr.state.stack_push_value.as_integer().lo(),
            cb.curr.state.aux0.expr(),
        );
        cb.require_equal(
            format!("{}, stack_push_value(0).hi == aux1(0)", Self::NAME),
            cb.curr.state.stack_push_value.as_integer().hi(),
            cb.curr.state.aux1.expr(),
        );

        // TODO: remove the range check if we are sure the operands has the correct type
        match N_BYTES {
            NUM_OF_BYTES_U8 | NUM_OF_BYTES_U16 | NUM_OF_BYTES_U32 | NUM_OF_BYTES_U64
            | NUM_OF_BYTES_U128 => {
                RangeCheckGadget::<_, N_BYTES>::construct(cb, cb.curr.state.aux0.expr());
                cb.require_zero(
                    format!("{}, stack_push_value(0).hi == 0", Self::NAME),
                    cb.curr.state.aux1.expr(),
                );
            }
            NUM_OF_BYTES_U256 => {
                RangeCheckGadget::<_, NUM_OF_BYTES_U128>::construct(cb, cb.curr.state.aux0.expr());
                RangeCheckGadget::<_, NUM_OF_BYTES_U128>::construct(cb, cb.curr.state.aux1.expr());
            }
            _ => unreachable!(),
        };

        cb.require_zero(
            format!("{}, stack_push_value_header(0) == false", Self::NAME),
            cb.curr.state.stack_push_value_header.expr(),
        );

        cb.require_equal(
            format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
            cb.curr.state.stack_push_version.expr(),
            cb.curr.state.clk.expr(),
        );

        cb.require_no_stack_pop();
        cb.require_no_local_op();

        cb.require_state_transition(vec![
            (FRAME_INDEX, Transition::Same),
            (MODULE_INDEX, Transition::Same),
            (FUNCTION_INDEX, Transition::Same),
            (SP, Transition::Delta(1.expr())),
            (PC, Transition::Delta(1.expr())),
        ]);

        Ld {
            phantom_data: PhantomData,
        }
    }
}
