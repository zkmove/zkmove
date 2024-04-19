use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::SubIndexGadget;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct ReadRefStage1<F> {
    phantom_data: PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for ReadRefStage1<F> {
    const NAME: &'static str = "ReadRef_Stage1";
    const OPCODE: Opcode = Opcode::ReadRef;
    const EXECUTION_STATE: ExecutionState = ExecutionState::ReadRefStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let next_row_state = cb.step_state_at_offset(1);

        cb.first_row(|cb| {
            cb.require_equal(
                format!("{}, step_counter(0) == 4", Self::NAME),
                cb.curr.state.step_counter.expr(),
                4u64.expr(),
            );
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                cb.curr.state.stack_pop_sub_index.expr(),
            );
        });

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            cb.curr.state.stack_pop_index.expr(),
            cb.curr.state.sp.expr(),
        );
        //TODO: super::common::fake_empty_stack_push();
        //TODO: super::common::fake_local_read_zero();
        cb.require_equal(
            format!("{}, sp(1) == sp(0)", Self::NAME),
            next_row_state.sp.expr(),
            cb.curr.state.sp.expr(),
        );

        cb.not_last_row(|cb| {
            cb.require_equal(
                format!(
                    "{}, stack_pop_sub_index(1) == stack_pop_sub_index(0) + 1",
                    Self::NAME
                ),
                next_row_state.stack_pop_sub_index.expr(),
                cb.curr.state.stack_pop_sub_index.expr() + 1u64.expr(),
            );
        });
        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::ReadRefStage2);
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Same),
            ]);
        });

        ReadRefStage1 {
            phantom_data: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReadRefStage2<F: Field> {
    header_sub_index: Cell<F>,
    sub_index_gadget: SubIndexGadget<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for ReadRefStage2<F> {
    const NAME: &'static str = "ReadRef_Stage2";
    const OPCODE: Opcode = Opcode::ReadRef;
    const EXECUTION_STATE: ExecutionState = ExecutionState::ReadRefStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_sub_index = cb.query_cell();
        let next_row_state = cb.step_state_at_offset(1);

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::ReadRefStage1);

            //TODO: find better repr for value flag

            // if local_read_value_flag(0) == HEADER {
            //     step_counter(0) == local_read_value(0).f_len;
            // } else {
            //     step_counter(0) == 1;
            // }

            let local_frame_index = cb.step_state_at_offset(-3).stack_pop_value.expr();
            let local_index = cb.step_state_at_offset(-2).stack_pop_value.expr();
            let local_sub_index = cb.step_state_at_offset(-1).stack_pop_value.expr();
            cb.require_equal(
                format!(
                    "{}, local_frame_index(0) == stack_pop_value(-3)",
                    Self::NAME
                ),
                cb.curr.state.local_frame_index.expr(),
                local_frame_index,
            );
            cb.require_equal(
                format!("{}, local_index(0) == stack_pop_value(-2)", Self::NAME),
                cb.curr.state.local_index.expr(),
                local_index,
            );
            cb.require_equal(
                format!("{}, local_sub_index(0) == stack_pop_value(-1)", Self::NAME),
                cb.curr.state.local_sub_index.expr(),
                local_sub_index,
            );

            cb.require_equal(
                format!("{}, header_sub_index(0) == local_sub_index(0)", Self::NAME),
                header_sub_index.expr(),
                cb.curr.state.local_sub_index.expr(),
            );
        });
        cb.require_equal(
            format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
            cb.curr.state.stack_push_index.expr(),
            cb.curr.state.sp.expr(),
        );

        let sub_index_gadget = SubIndexGadget::construct(
            cb,
            header_sub_index.expr(),
            cb.curr.state.stack_push_index.expr(),
            cb.curr.state.local_sub_index.expr(),
            Self::NAME,
        );

        cb.require_equal(
            format!("{}, stack_push_value(0) == local_read_value(0)", Self::NAME),
            cb.curr.state.stack_push_value.expr(),
            cb.curr.state.local_read_value.expr(),
        );
        cb.require_equal(
            format!(
                "{}, stack_push_value_flag(0) == local_read_value_flag(0)",
                Self::NAME
            ),
            cb.curr.state.stack_push_value_flag.expr(),
            cb.curr.state.local_read_value_flag.expr(),
        );
        cb.require_equal(
            format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
            cb.curr.state.stack_push_version.expr(),
            cb.curr.state.clk.expr(),
        );
        //TODO: local_read_version(0) < clk(0);

        cb.require_equal(
            format!(
                "{}, local_write_value(0) == local_read_value(0)",
                Self::NAME
            ),
            cb.curr.state.local_write_value.expr(),
            cb.curr.state.local_read_value.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value_flag(0) == local_read_value_flag(0)",
                Self::NAME
            ),
            cb.curr.state.local_write_value_flag.expr(),
            cb.curr.state.local_read_value_flag.expr(),
        );
        cb.require_equal(
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
            cb.curr.state.local_write_version.expr(),
            cb.curr.state.clk.expr(),
        );

        //TODO: super::common::fake_empty_stack_pop();

        cb.require_equal(
            format!("{}, sp(1) == sp(0)", Self::NAME),
            next_row_state.sp.expr(),
            cb.curr.state.sp.expr(),
        );

        cb.not_last_row(|cb| {
            cb.require_equal(
                format!(
                    "{}, local_frame_index(1) == local_frame_index(0)",
                    Self::NAME
                ),
                next_row_state.local_frame_index.expr(),
                cb.curr.state.local_frame_index.expr(),
            );
            cb.require_equal(
                format!("{}, local_index(1) == local_index(0)", Self::NAME),
                next_row_state.local_index.expr(),
                cb.curr.state.local_index.expr(),
            );
            let header_sub_index_next = cb.cell_at_offset(&header_sub_index, 1).expr();
            cb.require_equal(
                format!("{}, header_sub_index(1) == header_sub_index(0)", Self::NAME),
                header_sub_index_next,
                header_sub_index.expr(),
            );
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        ReadRefStage2 {
            header_sub_index,
            sub_index_gadget,
        }
    }
}
