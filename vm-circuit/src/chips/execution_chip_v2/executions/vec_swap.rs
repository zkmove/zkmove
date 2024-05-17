use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::{
    ExecutionState, ExtendedSubIndex, ValueHeader, DEPTH_POW_OF_ONE_LEVEL, REFERENCE_VALUE_FLEN,
};
use crate::chips::execution_chip_v2::step_v2::{
    AUX0, AUX1, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, OPCODE, PC, SP,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::utils::cell_manager::Cell;
use gadgets::util::Expr;
use std::iter::once;
use types::Field;

#[derive(Clone)]
pub struct VecSwapStage_1<F> {
    index1: Cell<F>,
    index2: Cell<F>,
}
impl<F: Field> InstructionGadgetV2<F> for VecSwapStage_1<F> {
    const NAME: &'static str = "VecSwap_Stage1";
    const OPCODE: Opcode = Opcode::VecSwap;
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecSwapStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let index1 = cb.query_cell();
        let index2 = cb.query_cell();

        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                cb.curr.state.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );
            cb.require_equal(
                "step_counter(0)==2",
                cb.curr.state.step_counter.expr(),
                2u64.expr(),
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
        cb.require_no_stack_push();
        cb.require_no_local_op();
        let step_prev = cb.step_state_at_offset(-1);
        cb.last_row(|cb| {
            cb.require_equal(
                "index1(0) == stack_pop_value(0)",
                index1.expr(),
                cb.curr.state.stack_pop_value.expr(),
            );
            cb.require_equal(
                "index2(0) == stack_pop_value(-1)",
                index2.expr(),
                step_prev.stack_pop_value.expr(),
            );
        });
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
            .chain(once((SP, Transition::Delta((-1).expr()))))
            .collect(),
        );
        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::VecSwapStage2);
            cb.require_cell_transition(index1.clone(), Transition::Same);
            cb.require_cell_transition(index2.clone(), Transition::Same);
        });
        VecSwapStage_1 { index1, index2 }
    }
}
#[derive(Clone)]
pub struct VecSwapStage_2<F> {
    index1: Cell<F>,
    index2: Cell<F>,
    ref_local_sub_index: Cell<F>,
}
impl<F: Field> InstructionGadgetV2<F> for VecSwapStage_2<F> {
    const NAME: &'static str = "VecSwap_Stage2";
    const OPCODE: Opcode = Opcode::VecSwap;
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecSwapStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let index1 = cb.query_cell();
        let index2 = cb.query_cell();
        let ref_local_sub_index = cb.query_cell();

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::VecSwapStage1);
            cb.require_equal(
                "opcode == Self::OPCODE",
                cb.curr.state.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );

            cb.require_equal(
                "step_counter(0)==4",
                cb.curr.state.step_counter.expr(),
                REFERENCE_VALUE_FLEN.expr(),
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
        cb.require_equal(
            "stack_pop_sub_index(0) == 4 - step_counter(0)",
            cb.curr.state.stack_pop_sub_index.expr(),
            4u64.expr() - cb.curr.state.step_counter.expr(),
        );
        cb.last_row(|cb| {
            cb.require_equal(
                "ref_local_sub_index(0) == stack_pop_value(0)",
                ref_local_sub_index.expr(),
                cb.curr.state.stack_pop_value.expr(),
            );
        });

        cb.require_no_stack_push();
        cb.require_no_local_op();

        // --- constrain next step

        // TODO: enable them for vec_swap as a whole
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
        cb.require_cell_transition(index1.clone(), Transition::Same);
        cb.require_cell_transition(index2.clone(), Transition::Same);

        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
        });

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::VecSwapStage3);
            // keep ref_local_sub_index same
            cb.require_cell_transition(ref_local_sub_index.clone(), Transition::Same);
        });
        Self {
            index1,
            index2,
            ref_local_sub_index,
        }
    }
}

/// Stage 3/4 move local value of index1/index2 to stack
#[derive(Clone)]
pub struct VecSwapStage_3_Or_4<F, const THREE: bool> {
    index1: Cell<F>,
    index2: Cell<F>,
    ref_local_sub_index: Cell<F>,
    value_len: Cell<F>,
}
impl<F: Field, const THREE: bool> VecSwapStage_3_Or_4<F, THREE> {
    const PREV_STATE: ExecutionState = if THREE {
        ExecutionState::VecSwapStage2
    } else {
        ExecutionState::VecSwapStage3
    };
    const NEXT_STATE: ExecutionState = if THREE {
        ExecutionState::VecSwapStage4
    } else {
        ExecutionState::VecSwapStage5
    };
}
impl<F: Field, const THREE: bool> InstructionGadgetV2<F> for VecSwapStage_3_Or_4<F, THREE> {
    const NAME: &'static str = if THREE {
        "VecSwap_Stage_3"
    } else {
        "VecSwap_Stage_4"
    };
    const OPCODE: Opcode = Opcode::VecSwap;
    const EXECUTION_STATE: ExecutionState = if THREE {
        ExecutionState::VecSwapStage3
    } else {
        ExecutionState::VecSwapStage4
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let index1 = cb.query_cell();
        let index2 = cb.query_cell();
        let ref_local_sub_index = cb.query_cell();
        let value_len = cb.query_cell();
        let extended_sub_index = ExtendedSubIndex::<_, 8>::construct(
            cb,
            "ref_local_sub_index",
            ref_local_sub_index.expr(),
        );

        let step_curr = cb.curr.state.clone();
        cb.first_row(|cb| {
            cb.require_prev_state(Self::PREV_STATE);
        });
        cb.last_row(|cb| {
            cb.require_next_state(Self::NEXT_STATE);
        });

        cb.require_no_stack_pop();

        // --- stack push constraints
        cb.require_equal(
            "stack_push_index(0) == sp(0)+1",
            step_curr.stack_push_index.expr(),
            step_curr.sp.expr() + 1u64.expr(),
        );
        // sub_index at first row must be zero
        cb.first_row(|cb| {
            cb.require_zero(
                "stack_push_sub_index(0)==0",
                step_curr.stack_push_sub_index.expr(),
            );
        });

        // value at first row must be a header
        cb.first_row(|cb| {
            cb.require_true(
                "stack_push_value_header(0)==true",
                step_curr.stack_push_value_header.expr(),
            );
            let header = ValueHeader::pair(value_len.expr(), step_curr.step_counter.expr());
            cb.require_equal(
                "step_counter(0) == stack_push_value(0).flen",
                header.expr(),
                step_curr.stack_push_value.expr(),
            );
        });

        // -- local op constraints
        cb.first_row(|cb| {
            // only need to look back on stack_pop_value for stage3
            if THREE {
                let reference_local_frame_index =
                    cb.cell_at_offset(&step_curr.stack_pop_value, -3).expr();
                cb.require_equal(
                    "local_frame_index(0) == stack_pop_value(-3)",
                    step_curr.local_frame_index.expr(),
                    reference_local_frame_index,
                );
                let reference_local_index =
                    cb.cell_at_offset(&step_curr.stack_pop_value, -2).expr();
                cb.require_equal(
                    "local_index(0) == stack_pop_value(-2)",
                    step_curr.local_index.expr(),
                    reference_local_index,
                );
                let reference_sub_index = cb.cell_at_offset(&step_curr.stack_pop_value, -1).expr();
                cb.require_equal(
                    "ref_local_sub_index(0) == stack_pop_value(-1)",
                    ref_local_sub_index.expr(),
                    reference_sub_index,
                );
            }
        });

        cb.require_equal(
            format!("local_sub_index(0) == concat(ref_local_sub_index(0),{},nonzero(stack_push_sub_index(0)))", if THREE { "index1" } else { "index2"}),
            step_curr.local_sub_index.expr(),
            extended_sub_index.concat_sub_index(
                if THREE { index1.expr() } else { index2.expr() }
                    + step_curr.stack_push_sub_index.expr() * DEPTH_POW_OF_ONE_LEVEL.expr(),
            )
        );
        cb.require_zero(
            "local_read_value_invalid(0) == false",
            step_curr.local_read_value_invalid.expr(),
        );
        cb.require_equal(
            "local_read_value(0)==stack_push_value(0)",
            step_curr.local_read_value.expr(),
            step_curr.stack_push_value.expr(),
        );
        cb.require_equal(
            "local_read_value_header(0)==stack_push_value_header(0)",
            step_curr.local_read_value_header.expr(),
            step_curr.stack_push_value_header.expr(),
        );

        // TODO: check the constraints
        // step_curr.local_read_version.expr() < clk;
        cb.require_equal(
            "local_write_version(0)==clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_true(
            "local_write_value_invalid(0) == true",
            step_curr.local_write_value_invalid.expr(),
        );

        cb.last_row(|cb| {
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

        // sp = sp+1 for last row
        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Delta(1u64.expr()))]);
        });

        cb.require_cell_transition(step_curr.local_frame_index.clone(), Transition::Same);
        cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
        cb.require_cell_transition(ref_local_sub_index.clone(), Transition::Same);
        cb.require_cell_transition(index1.clone(), Transition::Same);
        cb.require_cell_transition(index2.clone(), Transition::Same);

        Self {
            index1,
            index2,
            ref_local_sub_index,
            value_len,
        }
    }
}

/// Stage 5/6 move local value of index1/index2 to stack
#[derive(Clone)]
pub struct VecSwapStage_5_Or_6<F, const FIVE: bool> {
    index1: Cell<F>,
    index2: Cell<F>,
    ref_local_sub_index: Cell<F>,
    value_len: Cell<F>,
}
/// Stage 5/6 pop from stack and write to local of index1/index2
impl<F: Field, const FIVE: bool> VecSwapStage_5_Or_6<F, FIVE> {
    const PREV_STATE: ExecutionState = if FIVE {
        ExecutionState::VecSwapStage4
    } else {
        ExecutionState::VecSwapStage5
    };
}
impl<F: Field, const FIVE: bool> InstructionGadgetV2<F> for VecSwapStage_5_Or_6<F, FIVE> {
    const NAME: &'static str = if FIVE {
        "VecSwap_Stage_5"
    } else {
        "VecSwap_Stage_6"
    };
    const OPCODE: Opcode = Opcode::VecSwap;
    const EXECUTION_STATE: ExecutionState = if FIVE {
        ExecutionState::VecSwapStage5
    } else {
        ExecutionState::VecSwapStage6
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let index1 = cb.query_cell();
        let index2 = cb.query_cell();
        let ref_local_sub_index = cb.query_cell();
        let value_len = cb.query_cell();
        let extended_sub_index = ExtendedSubIndex::<_, 8>::construct(
            cb,
            "ref_local_sub_index",
            ref_local_sub_index.expr(),
        );

        let step_curr = cb.curr.state.clone();
        cb.first_row(|cb| {
            cb.require_prev_state(Self::PREV_STATE);
        });
        cb.last_row(|cb| {
            if FIVE {
                cb.require_next_state(ExecutionState::VecSwapStage6);
            }
        });
        cb.require_no_stack_push();

        // --- stack push constraints
        cb.require_equal(
            "stack_pop_index(0) == sp(0)",
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        // sub_index at first row must be zero
        cb.first_row(|cb| {
            cb.require_zero(
                "stack_pop_sub_index(0)==0",
                step_curr.stack_pop_sub_index.expr(),
            );
        });

        // value at first row must be a header
        cb.first_row(|cb| {
            cb.require_true(
                "stack_pop_value_header(0)==true",
                step_curr.stack_pop_value_header.expr(),
            );
            let header = ValueHeader::pair(value_len.expr(), step_curr.step_counter.expr());
            cb.require_equal(
                "step_counter(0) == stack_pop_value(0).flen",
                header.expr(),
                step_curr.stack_pop_value.expr(),
            );
        });

        // -- local op constraints
        cb.require_equal(
            format!("local_sub_index(0) == concat(ref_local_sub_index(0),{},nonzero(stack_pop_sub_index(0)))", if FIVE { "index1" } else { "index2"}),
            step_curr.local_sub_index.expr(),
            extended_sub_index.concat_sub_index(
                if FIVE { index1.expr() } else { index2.expr() }
                    + step_curr.stack_pop_sub_index.expr() * DEPTH_POW_OF_ONE_LEVEL.expr(),
            )
        );

        cb.require_true(
            "local_read_value_invalid(0) == true",
            step_curr.local_read_value_invalid.expr(),
        );
        // TODO: check the constraints
        // step_curr.local_read_version.expr();
        cb.require_zero(
            "local_write_value_invalid(0) == false",
            step_curr.local_write_value_invalid.expr(),
        );
        cb.require_equal(
            "stack_pop_value(0)==local_write_value(0)",
            step_curr.stack_pop_value.expr(),
            step_curr.local_write_value.expr(),
        );
        cb.require_equal(
            "local_write_value_header(0)==stack_pop_value_header(0)",
            step_curr.stack_pop_value_header.expr(),
            step_curr.local_write_value_header.expr(),
        );
        cb.require_equal(
            "local_write_version(0)==clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );

        if FIVE {
            cb.last_row(|cb| {
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
        }
        // sp = sp-1 for last row
        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
        });

        let constraints = |cb: &mut ConstraintBuilderV2<F>| {
            cb.require_cell_transition(step_curr.local_frame_index.clone(), Transition::Same);
            cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
            cb.require_cell_transition(ref_local_sub_index.clone(), Transition::Same);
            cb.require_cell_transition(index1.clone(), Transition::Same);
            cb.require_cell_transition(index2.clone(), Transition::Same);
        };
        if FIVE {
            constraints(cb);
        } else {
            cb.not_last_row(|cb| {
                constraints(cb);
            });
        }

        Self {
            index1,
            index2,
            ref_local_sub_index,
            value_len,
        }
    }
}
