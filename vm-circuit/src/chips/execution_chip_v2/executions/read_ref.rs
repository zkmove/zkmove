use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::ExtendedSubIndex;
use crate::chips::execution_chip_v2::executions::ValueHeader;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
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
        cb.require_no_stack_push();
        cb.require_no_local_op();

        cb.require_state_transition(vec![(SP, Transition::Same)]);
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
    header: ValueHeader<F>,
    header_sub_index: Cell<F>,
    header_sub_index_ext: ExtendedSubIndex<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for ReadRefStage2<F> {
    const NAME: &'static str = "ReadRef_Stage2";
    const OPCODE: Opcode = Opcode::ReadRef;
    const EXECUTION_STATE: ExecutionState = ExecutionState::ReadRefStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header = ValueHeader::new(cb);
        let header_sub_index = cb.query_cell();
        let next_row_state = cb.step_state_at_offset(1);
        let header_sub_index_ext =
            ExtendedSubIndex::<_, 8>::construct(cb, "header_sub_index", header_sub_index.expr());

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::ReadRefStage1);

            //if !local_read_value_header(0) { step_counter(0) == 1; }
            cb.require_zero(
                format!(
                    "{}, (1 - local_read_value_header(0)) * (step_counter(0) - 1) == 0",
                    Self::NAME
                ),
                (1u64.expr() - cb.curr.state.local_read_value_header.expr())
                    * (cb.curr.state.step_counter.expr() - 1u64.expr()),
            );

            //if local_read_value_header(0) { step_counter(0) == local_read_value(0).f_len; }
            cb.require_equal(
                format!("{}, local_read_value(0) == header", Self::NAME),
                cb.curr.state.local_read_value.expr(),
                header.expr(),
            );
            cb.require_zero(
                format!(
                    "{}, local_read_value_header(0) * (step_counter(0) - header.flen) == 0",
                    Self::NAME
                ),
                cb.curr.state.local_read_value_header.expr()
                    * (cb.curr.state.step_counter.expr() - header.flen.expr()),
            );

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

        cb.require_equal(
            format!("{}, local_sub_index(0) == concat(header_sub_index(0), nonzero(stack_push_sub_index(0)))" , Self::NAME),
            cb.curr.state.local_sub_index.expr(),
            header_sub_index_ext.concat_sub_index(cb.curr.state.stack_push_sub_index.expr()),
        );

        cb.require_equal(
            format!("{}, stack_push_value(0) == local_read_value(0)", Self::NAME),
            cb.curr.state.stack_push_value.expr(),
            cb.curr.state.local_read_value.expr(),
        );
        cb.require_equal(
            format!(
                "{}, stack_push_value_header(0) == local_read_value_header(0)",
                Self::NAME
            ),
            cb.curr.state.stack_push_value_header.expr(),
            cb.curr.state.local_read_value_header.expr(),
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
                "{}, local_write_value_invalid(0) == local_read_value_invalid(0)",
                Self::NAME
            ),
            cb.curr.state.local_write_value_invalid.expr(),
            cb.curr.state.local_read_value_invalid.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value_header(0) == local_read_value_header(0)",
                Self::NAME
            ),
            cb.curr.state.local_write_value_header.expr(),
            cb.curr.state.local_read_value_header.expr(),
        );
        cb.require_equal(
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
            cb.curr.state.local_write_version.expr(),
            cb.curr.state.clk.expr(),
        );

        cb.require_no_stack_pop();

        cb.require_state_transition(vec![(SP, Transition::Same)]);

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
            header,
            header_sub_index,
            header_sub_index_ext,
        }
    }
}
