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
use std::marker::PhantomData;
use types::Field;

#[derive(Copy, Clone, Default)]
pub struct VecPushBackStage1<F> {
    phantom_data: PhantomData<F>,
}
impl<F: Field> InstructionGadgetV2<F> for VecPushBackStage1<F> {
    const NAME: &'static str = "VecPushBackStage1";
    const OPCODE: Opcode = Opcode::VecPushBack;
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecPushBackStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::VecPushBackStage2);
        });

        cb.first_row(|cb| {
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
            "stack_pop_index(0) == sp(0)-1",
            cb.curr.state.stack_pop_index.expr(),
            cb.curr.state.sp.expr(),
        );
        cb.require_equal(
            "stack_pop_sub_index(0) == 4 - step_counter(0)",
            cb.curr.state.stack_pop_sub_index.expr(),
            REFERENCE_VALUE_FLEN.expr() - cb.curr.state.step_counter.expr(),
        );

        // TODO: stack_pop_version(0) < clk(0);
        cb.require_no_stack_push();
        cb.require_no_local_op();

        // --- constrain next step

        cb.require_state_transition(
            [
                FRAME_INDEX,
                MODULE_INDEX,
                FUNCTION_INDEX,
                PC,
                OPCODE,
                AUX0,
                AUX1,
                SP,
            ]
            .into_iter()
            .map(|s| (s, Transition::Same))
            .collect(),
        );
        Self::default()
    }
}

/// stage2 update parent from top to bottom
#[derive(Clone)]
pub struct VecPushBackStage2<F> {
    vector_sub_index: Cell<F>,
    extended_local_sub_index_of_next_row: ExtendedSubIndex<F, 8>,
    vector_origin_len: Cell<F>,
    vector_origin_flen: Cell<F>,
}
impl<F: Field> VecPushBackStage2<F> {
    const PREV_STATE: ExecutionState = ExecutionState::VecPushBackStage1;
    const NEXT_STATE: ExecutionState = ExecutionState::VecPushBackStage3;
}
impl<F: Field> InstructionGadgetV2<F> for VecPushBackStage2<F> {
    const NAME: &'static str = "VecPushBackStage2";
    const OPCODE: Opcode = Opcode::VecPushBack;
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecPushBackStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_next = cb.step_state_at_offset(1);
        let step_prev = cb.step_state_at_offset(-1);
        let vector_sub_index = cb.query_cell();
        let next_local_sub_index = step_next.local_sub_index.clone();
        let extended_local_sub_index_of_next_row = ExtendedSubIndex::construct(
            cb,
            "extended_local_sub_index_of_next_row",
            next_local_sub_index.expr(),
        );

        // make sure len and flen are < u16
        // TODO: what happens if vector len > u16
        let vector_origin_len = cb.query_u16();
        let vector_origin_flen = cb.query_u16();

        cb.require_no_stack_push();
        cb.require_no_stack_pop();

        cb.first_row(|cb| {
            cb.require_prev_state(Self::PREV_STATE);
        });
        cb.last_row(|cb| {
            cb.require_next_state(Self::NEXT_STATE);
        });

        // -- local op constraints
        cb.first_row(|cb| {
            // only need to look back on stack_pop_value for stage3

            let reference_local_frame_index =
                cb.cell_at_offset(&step_curr.stack_pop_value, -3).expr();
            cb.require_equal(
                "local_frame_index(0) == stack_pop_value(-3)",
                step_curr.local_frame_index.expr(),
                reference_local_frame_index,
            );
            let reference_local_index = cb.cell_at_offset(&step_curr.stack_pop_value, -2).expr();
            cb.require_equal(
                "local_index(0) == stack_pop_value(-2)",
                step_curr.local_index.expr(),
                reference_local_index,
            );
            let reference_sub_index = cb.cell_at_offset(&step_curr.stack_pop_value, -1).expr();
            cb.require_equal(
                "vector_sub_index(0) == stack_pop_value(-1)",
                vector_sub_index.expr(),
                reference_sub_index,
            );

            cb.require_zero("local_sub_index(0)==0", step_curr.local_sub_index.expr());
        });

        cb.not_first_row(|cb| {
            cb.require_equal(
                "local_frame_index(0) == local_frame_index(-1)",
                step_curr.local_frame_index.expr(),
                step_prev.local_frame_index.expr(),
            );
            cb.require_equal(
                "local_index(0) == local_index(-1)",
                step_curr.local_index.expr(),
                step_prev.local_index.expr(),
            );
            let prev_vector_sub_index = cb.cell_at_offset(&vector_sub_index, -1);
            cb.require_equal(
                "vector_sub_index(0) == vector_sub_index(-1)",
                vector_sub_index.expr(),
                prev_vector_sub_index.expr(),
            );
        });

        cb.not_last_row(|cb| {
            cb.require_equal(
                "local_sub_index(0) == local_sub_index(1).parent()",
                step_curr.local_sub_index.expr(),
                extended_local_sub_index_of_next_row.get_parent_sub_index(),
            );
        });
        cb.last_row(|cb| {
            cb.require_equal(
                "local_sub_index(0) == vector_sub_index(0)",
                step_curr.local_sub_index.expr(),
                vector_sub_index.expr(),
            );
        });
        cb.require_true(
            "local_read_value_header(0) == true",
            step_curr.local_read_value_header.expr(),
        );
        cb.require_zero(
            "local_read_value_invalid(0)==false",
            step_curr.local_read_value_invalid.expr(),
        );
        cb.require_true(
            "local_write_value_header(0) == true",
            step_curr.local_write_value_header.expr(),
        );
        cb.require_zero(
            "local_write_value_invalid(0)==false",
            step_curr.local_write_value_invalid.expr(),
        );
        // TODO:
        //         local_read_version(0) < clk(0);
        //         local_write_version(0) == clk(0);

        cb.not_last_row(|cb| {
            cb.require_equal(
                "local_write_value(0) - local_read_value(0) == local_write_value(1) - local_read_value(1)",
                step_curr.local_read_value.expr() + step_next.local_write_value.expr(),
                step_curr.local_write_value.expr() + step_next.local_read_value.expr(),
            );
        });
        cb.last_row(|cb| {
            cb.require_equal(
                "local_read_value(0) == ValueHeader::new(vector_origin_len, vector_origin_flen)",
                step_curr.local_read_value.expr(),
                ValueHeader::pair(vector_origin_len.expr(), vector_origin_flen.expr()).expr(),
            );
            cb.require_equal(
                "local_write_value(0) == ValueHeader::new(vector_origin_len + 1, vector_origin_flen + step_counter(1))",
                step_curr.local_write_value.expr(),
                ValueHeader::pair(vector_origin_len.expr() + 1u64.expr(),
                                  vector_origin_flen.expr() + step_next.step_counter.expr()).expr()
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
                SP,
            ]
            .into_iter()
            .map(|s| (s, Transition::Same))
            .collect(),
        );

        Self {
            vector_sub_index,
            extended_local_sub_index_of_next_row,
            vector_origin_len,
            vector_origin_flen,
        }
    }
}

#[derive(Clone)]
pub struct VecPushBackStage3<F> {
    vector_sub_index: Cell<F>,
    extended_vector_sub_index: ExtendedSubIndex<F, 8>,
    vector_origin_len: Cell<F>,
    elem_len: Cell<F>,
}
impl<F: Field> VecPushBackStage3<F> {
    const PREV_STATE: ExecutionState = ExecutionState::VecPushBackStage2;
}
impl<F: Field> InstructionGadgetV2<F> for VecPushBackStage3<F> {
    const NAME: &'static str = "VecPushBackStage3";
    const OPCODE: Opcode = Opcode::VecPushBack;
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecPushBackStage3;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let vector_sub_index = cb.query_cell();
        let extended_vector_sub_index =
            ExtendedSubIndex::construct(cb, "extended_vector_sub_index", vector_sub_index.expr());
        let vector_origin_len = cb.query_u16();
        let elem_len = cb.query_u16();

        cb.require_no_stack_push();

        cb.first_row(|cb| {
            cb.require_prev_state(Self::PREV_STATE);
        });
        let prev_vector_sub_index = cb.cell_at_offset(&vector_sub_index, -1);
        cb.require_equal(
            "vector_sub_index(0) == vector_sub_index(-1)",
            vector_sub_index.expr(),
            prev_vector_sub_index.expr(),
        );

        cb.require_equal(
            "local_frame_index(0) == local_frame_index(-1)",
            step_curr.local_frame_index.expr(),
            step_prev.local_frame_index.expr(),
        );
        cb.require_equal(
            "local_index(0) == local_index(-1)",
            step_curr.local_index.expr(),
            step_prev.local_index.expr(),
        );
        cb.require_equal(
            "local_sub_index(0)
            == extend_vector_sub_index.concat(vector_origin_len(0) + stack_pop_sub_index(0) << 16)",
            step_curr.local_sub_index.expr(),
            extended_vector_sub_index.concat_sub_index(
                vector_origin_len.expr()
                    + step_curr.stack_pop_sub_index.expr() * DEPTH_POW_OF_ONE_LEVEL.expr(),
            ),
        );
        cb.first_row(|cb| {
            cb.condition(step_curr.local_write_value_header.expr(), |cb| {
                cb.require_equal(
                    "local_write_value(0) == ValueHeader::new(elem_len(0), step_counter(0))",
                    step_curr.local_write_value.expr(),
                    ValueHeader::pair(elem_len.expr(), step_curr.step_counter.expr()).expr(),
                );
            });
            cb.condition(
                1u64.expr() - step_curr.local_write_value_header.expr(),
                |cb| {
                    cb.require_equal(
                        "step_counter(0)==1",
                        step_curr.step_counter.expr(),
                        1.expr(),
                    );
                },
            );
        });
        cb.require_true(
            "local_read_value_invalid(0) == true",
            step_curr.local_read_value_invalid.expr(),
        );
        cb.require_zero(
            "local_write_value_invalid(0) == false",
            step_curr.local_write_value_invalid.expr(),
        );

        // TODO:
        //         local_read_version(0) < clk(0);
        //         local_write_version(0) == clk(0);

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
        // TODO: not first row
        // stack_pop_sub_index(0) > stack_pop_sub_index(-1);

        cb.require_equal(
            "stack_pop_value(0)==local_write_value(0)",
            step_curr.stack_pop_value.expr(),
            step_curr.local_write_value.expr(),
        );
        cb.require_equal(
            "stack_pop_value_header(0)==local_write_value_header(0)",
            step_curr.stack_pop_value_header.expr(),
            step_curr.local_write_value_header.expr(),
        );
        // TODO: do it in common?
        cb.require_equal(
            "stack_pop_version(0)==clk(0)",
            step_curr.stack_pop_version.expr(),
            step_curr.clk.expr(),
        );

        // next
        cb.require_state_transition(
            [FRAME_INDEX, MODULE_INDEX, FUNCTION_INDEX]
                .into_iter()
                .map(|s| (s, Transition::Same))
                .collect(),
        );
        cb.not_last_row(|cb| {
            cb.require_state_transition(
                [PC, OPCODE, AUX0, AUX1, SP]
                    .into_iter()
                    .map(|s| (s, Transition::Same))
                    .collect(),
            );
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![
                (PC, Transition::Delta(1.expr())),
                (SP, Transition::Delta((-2).expr())),
            ]);
        });
        Self {
            vector_sub_index,
            extended_vector_sub_index,
            vector_origin_len,
            elem_len,
        }
    }
}
