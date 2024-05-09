use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::ExtendedSubIndex;
use crate::chips::execution_chip_v2::executions::MembershipGadget;
use crate::chips::execution_chip_v2::executions::SubIndexDepth;
use crate::chips::execution_chip_v2::executions::ValueHeader;
use crate::chips::execution_chip_v2::executions::DEPTH_POW_OF_ONE_LEVEL;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use gadgets::util::not;
use std::marker::PhantomData;
use types::Field;

///STAGE_POP_REF
#[derive(Clone, Debug)]
pub struct WriteRefStage1<F> {
    phantom_data: PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for WriteRefStage1<F> {
    const NAME: &'static str = "WriteRef_Stage1";
    const OPCODE: Opcode = Opcode::WriteRef;
    const EXECUTION_STATE: ExecutionState = ExecutionState::WriteRefStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );
            cb.require_equal(
                format!("{}, step_counter(0) == 4", Self::NAME),
                step_curr.step_counter.expr(),
                4u64.expr(),
            );
        });
        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_equal(
            format!(
                "{}, stack_pop_sub_index(0) == 4 - step_counter(0)",
                Self::NAME
            ),
            step_curr.stack_pop_sub_index.expr(),
            4u64.expr() - step_curr.step_counter.expr(),
        );
        cb.require_no_stack_push();
        cb.require_no_local_op();

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::WriteRefStage2);
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Same),
                (SP, Transition::Delta((-1).expr())),
            ]);
        });

        WriteRefStage1 {
            phantom_data: PhantomData,
        }
    }
}

///STAGE_INVALIDATE_OLD
#[derive(Clone, Debug)]
pub struct WriteRefStage2<F: Field> {
    header_sub_index: Cell<F>,
    header_flen_delta: Cell<F>,
    membership_gadget: MembershipGadget<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for WriteRefStage2<F> {
    const NAME: &'static str = "WriteRef_Stage2";
    const OPCODE: Opcode = Opcode::WriteRef;
    const EXECUTION_STATE: ExecutionState = ExecutionState::WriteRefStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_sub_index = cb.query_cell();
        let header_flen_delta = cb.query_cell();
        let membership_gadget = MembershipGadget::<_, 8>::construct(cb);
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::WriteRefStage1);

            let local_frame_index = cb.cell_at_offset(&step_curr.stack_pop_value, -3).expr();
            let local_index = cb.cell_at_offset(&step_curr.stack_pop_value, -2).expr();
            let local_sub_index = cb.cell_at_offset(&step_curr.stack_pop_value, -1).expr();
            cb.require_equal(
                format!(
                    "{}, local_frame_index(0) == stack_pop_value(-3)",
                    Self::NAME
                ),
                step_curr.local_frame_index.expr(),
                local_frame_index,
            );
            cb.require_equal(
                format!("{}, local_index(0) == stack_pop_value(-2)", Self::NAME),
                step_curr.local_index.expr(),
                local_index,
            );
            cb.require_equal(
                format!("{}, local_sub_index(0) == stack_pop_value(-1)", Self::NAME),
                step_curr.local_sub_index.expr(),
                local_sub_index,
            );

            cb.condition(step_curr.local_read_value_header.expr(), |cb| {
                let header = ValueHeader::new(cb);
                cb.require_equal(
                    format!("{}, local_read_value(0) == header", Self::NAME),
                    step_curr.local_read_value.expr(),
                    header.expr(),
                );
                cb.require_equal(
                    format!("{}, step_counter(0) == header.flen", Self::NAME),
                    step_curr.step_counter.expr(),
                    header.flen.expr(),
                );
                cb.require_equal(
                    format!(
                        "{}, header_flen_delta(0) == local_read_value(0).f_len",
                        Self::NAME
                    ),
                    header_flen_delta.expr(),
                    header.flen.expr(),
                );
            });
            cb.condition(not::expr(step_curr.local_read_value_header.expr()), |cb| {
                cb.require_equal(
                    format!("{}, step_counter(0) == 1", Self::NAME),
                    step_curr.step_counter.expr(),
                    1u64.expr(),
                );
                cb.require_equal(
                    format!(
                        "{}, header_flen_delta(0) == local_read_value(0).f_len",
                        Self::NAME
                    ),
                    header_flen_delta.expr(),
                    1u64.expr(),
                );
            });
            cb.require_equal(
                format!("{}, header_sub_index(0) == local_sub_index(0)", Self::NAME),
                header_sub_index.expr(),
                step_curr.local_sub_index.expr(),
            );
        });

        cb.not_first_row(|cb| {
            membership_gadget.configure(
                cb,
                header_sub_index.expr(),
                step_curr.local_sub_index.expr(),
                Self::NAME,
            );
        });

        //TODO: local_read_version(0) < clk(0);
        cb.require_equal(
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );

        cb.require_write_invalid_value();
        cb.require_no_stack_pop();
        cb.require_no_stack_push();
        cb.require_state_transition(vec![(SP, Transition::Same)]);
        cb.require_cell_transition(step_curr.local_frame_index.clone(), Transition::Same);
        cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
        cb.require_cell_transition(header_sub_index.clone(), Transition::Same);

        cb.not_last_row(|cb| {
            cb.require_cell_transition(header_flen_delta.clone(), Transition::Same);
        });

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::WriteRefStage3);
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Same),
            ]);
        });

        WriteRefStage2 {
            header_sub_index,
            header_flen_delta,
            membership_gadget,
        }
    }
}

///STAGE_WRITE_NEW
#[derive(Clone, Debug)]
pub struct WriteRefStage3<F: Field> {
    header_sub_index: Cell<F>,  //NOTICE: must be in the same column as stage 2.
    header_flen_delta: Cell<F>, //NOTICE: must be in the same column as stage 2.
    header_sub_index_ext: ExtendedSubIndex<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for WriteRefStage3<F> {
    const NAME: &'static str = "WriteRef_Stage3";
    const OPCODE: Opcode = Opcode::WriteRef;
    const EXECUTION_STATE: ExecutionState = ExecutionState::WriteRefStage3;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_sub_index = cb.query_cell();
        let header_flen_delta = cb.query_cell();
        let header_sub_index_ext =
            ExtendedSubIndex::<_, 8>::construct(cb, Self::NAME, header_sub_index.expr());
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::WriteRefStage2);

            let header_flen_delta_prev = cb.cell_at_offset(&header_flen_delta, -1).expr();
            cb.condition(step_curr.stack_pop_value_header.expr(), |cb| {
                let header = ValueHeader::new(cb);
                cb.require_equal(
                    format!("{}, stack_pop_value(0) == header", Self::NAME),
                    step_curr.stack_pop_value.expr(),
                    header.expr(),
                );
                cb.require_equal(
                    format!("{}, step_counter(0) == header.flen", Self::NAME),
                    step_curr.step_counter.expr(),
                    header.flen.expr(),
                );
                cb.require_equal(
                    format!(
                        "{}, header_flen_delta(0) == stack_pop_value(0).f_len - header_flen_delta(-1)",
                        Self::NAME
                    ),
                    header_flen_delta.expr(),
                    header.flen.expr() - header_flen_delta_prev.clone(),
                );
            });
            cb.condition(not::expr(step_curr.stack_pop_value_header.expr()), |cb| {
                cb.require_equal(
                    format!("{}, step_counter(0) == 1", Self::NAME),
                    step_curr.step_counter.expr(),
                    1u64.expr(),
                );
                cb.require_equal(
                    format!(
                        "{}, header_flen_delta(0) == stack_pop_value(0).f_len - header_flen_delta(-1)",
                        Self::NAME
                    ),
                    header_flen_delta.expr(),
                    1u64.expr() - header_flen_delta_prev,
                );
            });

            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                step_curr.stack_pop_sub_index.expr(),
            );
        });

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );

        cb.require_equal(
            format!("{}, local_sub_index(0) == concat(header_sub_index(0), nonzero(stack_pop_sub_index(0)))" , Self::NAME),
            step_curr.local_sub_index.expr(),
            header_sub_index_ext.concat_sub_index(step_curr.stack_pop_sub_index.expr()),
        );

        cb.require_read_invalid_value();
        // TODO: local_read_version(0) < clk(0);

        cb.require_equal(
            format!("{}, local_write_value(0) == stack_pop_value(0)", Self::NAME),
            step_curr.local_write_value.expr(),
            step_curr.stack_pop_value.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value_header(0) == stack_pop_value_header(0)",
                Self::NAME
            ),
            step_curr.local_write_value_header.expr(),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_equal(
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_no_stack_push();

        cb.not_last_row(|cb| {
            cb.require_cell_transition(step_curr.local_frame_index.clone(), Transition::Same);
            cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
            cb.require_cell_transition(header_sub_index.clone(), Transition::Same);
            cb.require_cell_transition(header_flen_delta.clone(), Transition::Same);
            cb.require_state_transition(vec![(PC, Transition::Same)]);
        });

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::WriteRefStage4);
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Delta((-1).expr())),
                (PC, Transition::Same),
            ]);
        });

        WriteRefStage3 {
            header_sub_index,
            header_flen_delta,
            header_sub_index_ext,
        }
    }
}

///STAGE_UPDATE_PARENT
#[derive(Clone, Debug)]
pub struct WriteRefStage4<F: Field> {
    header_sub_index: Cell<F>, //NOTICE: must be in the same column as prev stage.
    header_flen_delta: Cell<F>, //NOTICE: must be in the same column as prev stage.
    header_sub_index_depth: SubIndexDepth<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for WriteRefStage4<F> {
    const NAME: &'static str = "WriteRef_Stage4";
    const OPCODE: Opcode = Opcode::WriteRef;
    const EXECUTION_STATE: ExecutionState = ExecutionState::WriteRefStage4;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_sub_index = cb.query_cell(); //NOTICE: must be in the same column as stage 3.
        let header_flen_delta = cb.query_cell(); //NOTICE: must be in the same column as stage 3.
        let header_sub_index_prev = cb.cell_at_offset(&header_sub_index, -1).expr();
        let header_sub_index_depth =
            SubIndexDepth::<_, 8>::construct(cb, header_sub_index_prev.clone(), Self::NAME);
        let depth = cb.query_cell();
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::WriteRefStage3);

            cb.require_equal(
                format!(
                    "{}, header_sub_index(0) == header_sub_index(-1)",
                    Self::NAME
                ),
                header_sub_index.expr(),
                header_sub_index_prev,
            );
            cb.require_equal(
                format!(
                    "{}, step_counter(0) == header_sub_index(-1).depth()",
                    Self::NAME
                ),
                step_curr.step_counter.expr(),
                header_sub_index_depth.expr(),
            );
            let header_sub_index_prev = cb.cell_at_offset(&header_sub_index, -1).expr();
            cb.require_equal(
                format!(
                    "{}, header_sub_index(0) * 2^16 == header_sub_index(-1)",
                    Self::NAME
                ),
                header_sub_index.expr() * DEPTH_POW_OF_ONE_LEVEL.expr(),
                header_sub_index_prev,
            );
            let header_flen_delta_prev = cb.cell_at_offset(&header_flen_delta, -1).expr();
            cb.require_equal(
                format!(
                    "{}, header_flen_delta(0) == header_flen_delta(-1)",
                    Self::NAME
                ),
                header_flen_delta.expr(),
                header_flen_delta_prev,
            );
            let local_frame_index_prev = cb.cell_at_offset(&step_curr.local_frame_index, -1).expr();
            cb.require_equal(
                format!(
                    "{}, local_frame_index(0) == local_frame_index(-1)",
                    Self::NAME
                ),
                step_curr.local_frame_index.expr(),
                local_frame_index_prev,
            );
            let local_index_prev = cb.cell_at_offset(&step_curr.local_index, -1).expr();
            cb.require_equal(
                format!("{}, local_index(0) == local_index(-1)", Self::NAME),
                step_curr.local_index.expr(),
                local_index_prev,
            );
        });

        //TODO: local_read_version(0) < clk(0);
        cb.require_equal(
            format!("{}, local_sub_index(0) == header_sub_index(0)", Self::NAME),
            step_curr.local_sub_index.expr(),
            header_sub_index.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value(0) == local_read_value(0) + header_flen_delta(0)",
                Self::NAME
            ),
            step_curr.local_write_value.expr(),
            step_curr.local_read_value.expr() + header_flen_delta.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value_header(0) == local_read_value_header(0)",
                Self::NAME
            ),
            step_curr.local_write_value_header.expr(),
            step_curr.local_read_value_header.expr(),
        );
        cb.require_equal(
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_state_transition(vec![(SP, Transition::Same)]);

        cb.not_last_row(|cb| {
            let header_sub_index_next = cb.cell_at_offset(&header_sub_index, 1).expr();
            cb.require_equal(
                format!(
                    "{}, header_sub_index(1) * 2^16 == header_sub_index(0)",
                    Self::NAME
                ),
                header_sub_index_next * DEPTH_POW_OF_ONE_LEVEL.expr(),
                header_sub_index.expr(),
            );
            cb.require_cell_transition(header_flen_delta.clone(), Transition::Same);
            cb.require_cell_transition(step_curr.local_frame_index.clone(), Transition::Same);
            cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
        });

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::WriteRefStage4);
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Same),
            ]);
        });

        WriteRefStage4 {
            header_sub_index,
            header_flen_delta,
            header_sub_index_depth,
        }
    }
}
