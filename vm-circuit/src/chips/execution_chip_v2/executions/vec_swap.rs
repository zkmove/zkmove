use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::step_v2::{
    AUX0, AUX1, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, OPCODE, PC, SP,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::utils::cell_manager::Cell;
use gadgets::util::Expr;
use std::marker::PhantomData;
use types::Field;

pub struct VecSwapStage1<F> {
    phantom_data: PhantomData<F>,
}
impl<F: Field> InstructionGadgetV2<F> for VecSwapStage1<F> {
    const NAME: &'static str = "VecSwap_Stage1";
    const OPCODE: Opcode = Opcode::VecSwap;
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecSwapStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                cb.curr.state.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );
            cb.require_equal(
                "step_counter(0)==2",
                cb.curr.state.step_counter.expr(),
                1u64.expr(),
            );
        });

        cb.require_equal(
            "stack_pop_index(0) == sp(0)",
            cb.curr.state.stack_pop_index.expr(),
            cb.curr.state.sp.expr(),
        );
        cb.require_zero(
            "stack_pop_sub_index(0) == 0",
            cb.curr.state.stack_pop_sub_index.expr(),
        );

        cb.require_zero(
            "stack_pop_value_header(0) == false",
            cb.curr.state.stack_pop_value_header.expr(),
        );
        // TODO: check stack_pop_version<clk

        cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::VecSwapStage2);

            cb.require_state_transition(
                [
                    FRAME_INDEX,
                    MODULE_INDEX,
                    FUNCTION_INDEX,
                    PC,
                    OPCODE,
                    AUX0,
                    AUX1,
                ]
                .into_iter()
                .map(|s| (s, Transition::Same))
                .collect(),
            );
        });
        VecSwapStage1 {
            phantom_data: PhantomData,
        }
    }
}
pub struct VecSwapStage2<F> {
    phantom_data: PhantomData<F>,
}
impl<F: Field> InstructionGadgetV2<F> for VecSwapStage2<F> {
    const NAME: &'static str = "VecSwap_Stage2";
    const OPCODE: Opcode = Opcode::VecSwap;
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecSwapStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::VecSwapStage1);
            cb.require_equal(
                "opcode",
                cb.curr.state.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );

            // TODO: should we constrain this
            cb.require_equal(
                "step_counter(0)==4",
                cb.curr.state.step_counter.expr(),
                1u64.expr(),
            );
            cb.require_zero(
                "stack_pop_sub_index(0) == 0",
                cb.curr.state.stack_pop_sub_index.expr(),
            );

            cb.require_true(
                "stack_pop_value_header(0) == true",
                cb.curr.state.stack_pop_value_header.expr(),
            );
        });

        cb.not_first_row(|cb| {
            cb.require_zero(
                "stack_pop_value_header(0) == false",
                cb.curr.state.stack_pop_value_header.expr(),
            );
        });

        cb.require_equal(
            "stack_pop_index(0) == sp(0)",
            cb.curr.state.stack_pop_index.expr(),
            cb.curr.state.sp.expr(),
        );

        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

        cb.last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
        });

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::VecSwapStage3);
            cb.require_state_transition(
                [
                    FRAME_INDEX,
                    MODULE_INDEX,
                    FUNCTION_INDEX,
                    PC,
                    OPCODE,
                    AUX0,
                    AUX1,
                ]
                .into_iter()
                .map(|s| (s, Transition::Same))
                .collect(),
            );
        });
        Self {
            phantom_data: PhantomData,
        }
    }
}

pub struct VecSwapStage3<F> {
    is_source: Cell<F>,
    elem_idx: Cell<F>,
    phantom_data: PhantomData<F>,
}
impl<F: Field> InstructionGadgetV2<F> for VecSwapStage3<F> {
    const NAME: &'static str = "VecSwap_Stage3";
    const OPCODE: Opcode = Opcode::VecSwap;
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecSwapStage3;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let is_source = cb.query_bool();
        let idx = cb.query_cell();

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::VecSwapStage2);
        });

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::VecSwapStage4);
        });

        // FIXME: finish the work
        cb.first_row(|cb| {
            let _index2 = cb.step_state_at_offset(-6).stack_pop_value.expr();
            let _index1 = cb.step_state_at_offset(-5).stack_pop_value.expr();
            let _local_frame_index = cb.step_state_at_offset(-3).stack_pop_value.expr();
            let _local_index = cb.step_state_at_offset(-2).stack_pop_value.expr();
            let _local_sub_index = cb.step_state_at_offset(-1).stack_pop_value.expr();
        });

        Self {
            is_source,
            elem_idx: idx,
            phantom_data: PhantomData,
        }
    }
}
