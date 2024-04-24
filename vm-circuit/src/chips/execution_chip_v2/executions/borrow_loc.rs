use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::{ExecutionState, ValueHeader};
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct BorrowLoc<const MUTABLE: bool, F> {
    phantom_data: PhantomData<F>,
}
impl<const MUTABLE: bool, F: Field> InstructionGadgetV2<F> for BorrowLoc<MUTABLE, F> {
    const NAME: &'static str = "BorrowLoc";

    const OPCODE: Opcode = if MUTABLE {
        Opcode::MutBorrowLoc
    } else {
        Opcode::ImmBorrowLoc
    };
    const EXECUTION_STATE: ExecutionState = if MUTABLE {
        ExecutionState::MutBorrowLoc
    } else {
        ExecutionState::ImmBorrowLoc
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let next_row_state = cb.step_state_at_offset(1);
        cb.first_row(|cb| {
            cb.require_equal(
                format!("{}, step_counter(0) == 4", Self::NAME),
                cb.curr.state.step_counter.expr(),
                4u64.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_value(0) == (3,4)", Self::NAME),
                cb.curr.state.stack_push_value.expr(),
                ValueHeader::default().expr(),
            );
            cb.require_true(
                format!("{}, stack_push_value_header(0) == true", Self::NAME),
                cb.curr.state.stack_push_value_header.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                cb.curr.state.stack_push_sub_index.expr(),
            );

            // second row
            cb.require_equal(
                format!("{}, stack_push_value(1) = frame_index(0)", Self::NAME),
                next_row_state.stack_push_value.expr(),
                cb.curr.state.frame_index.expr(),
            );
        });

        cb.not_first_row(|cb| {
            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                cb.curr.state.stack_push_value_header.expr(),
            );
        });

        cb.require_equal(
            format!("{}, stack_push_index(0) == sp(0) + 1", Self::NAME),
            cb.curr.state.stack_push_index.expr(),
            cb.curr.state.sp.expr() + 1u64.expr(),
        );

        cb.require_equal(
            format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
            cb.curr.state.stack_push_version.expr(),
            cb.curr.state.clk.expr(),
        );

        //TODO: super::common::fake_empty_stack_pop(0);
        //TODO: super::common::fake_local_read_zero(0);

        cb.not_last_row(|cb| {
            cb.require_equal(
                format!(
                    "{}, stack_push_sub_index(1) == stack_push_sub_index(0) + 1",
                    Self::NAME
                ),
                next_row_state.stack_push_sub_index.expr(),
                cb.curr.state.stack_push_sub_index.expr() + 1u64.expr(),
            );
            cb.require_equal(
                format!("{}, step_counter(1) == step_counter(0) - 1", Self::NAME),
                next_row_state.step_counter.expr(),
                cb.curr.state.step_counter.expr() - 1u64.expr(),
            );
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

        cb.last_row(|cb| {
            // in the third row, 'stack_push_value(0) = aux0(0)'
            let stack_push_value_prev =
                cb.cell_at_offset(&cb.curr.state.stack_push_value.clone(), -1);
            cb.require_equal(
                format!("{}, stack_push_value(-1) == aux0(0)", Self::NAME),
                stack_push_value_prev.expr(),
                cb.curr.state.aux0.expr(),
            );

            cb.require_zero(
                format!("{}, stack_push_value(0) = 0", Self::NAME),
                cb.curr.state.stack_push_value.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_sub_index(0) == 3", Self::NAME),
                cb.curr.state.stack_push_sub_index.expr(),
                3u64.expr(),
            );
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Delta(1.expr())),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        BorrowLoc {
            phantom_data: PhantomData,
        }
    }
}
