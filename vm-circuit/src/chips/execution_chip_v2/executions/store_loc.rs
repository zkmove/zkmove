use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::{ExecutionState, ValueHeader};
use crate::chips::execution_chip_v2::step_v2::{
    AUX0, AUX1, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, OPCODE, PC, SP,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use gadgets::util::Expr;
use types::Field;

#[derive(Clone, Debug)]
pub struct StoreLocStage1<F> {
    local_value_header: ValueHeader<F>,
}

impl<F: Field> InstructionGadgetV2<F> for StoreLocStage1<F> {
    const NAME: &'static str = "StoreLoc_Stage1";
    const OPCODE: Opcode = Opcode::StLoc;
    const EXECUTION_STATE: ExecutionState = ExecutionState::StoreLocStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let value_len = cb.query_u16();
        let value_flen = cb.query_u16();
        let header = ValueHeader::pair(value_len.expr(), value_flen.expr());

        let step_curr = cb.curr.state.clone();

        cb.require_no_stack_pop();
        cb.require_no_stack_push();

        cb.first_row(|cb| {
            cb.condition(step_curr.local_read_value_header.expr(), |cb| {
                cb.require_equal(
                    "(len, flen) = local_read_value(0)",
                    step_curr.local_read_value.expr(),
                    header.expr(),
                );
                cb.require_equal(
                    "step_counter(0) == flen",
                    step_curr.step_counter.expr(),
                    value_flen.expr(),
                );
            });
            cb.condition(
                1u64.expr() - step_curr.local_read_value_header.expr(),
                |cb| {
                    cb.require_equal(
                        "step_counter(0) == 1",
                        step_curr.step_counter.expr(),
                        1u64.expr(),
                    );
                },
            );
        });
        cb.require_equal(
            "local_frame_index(0) == frame_index(0)",
            step_curr.local_frame_index.expr(),
            step_curr.frame_index.expr(),
        );
        // ensure local_index equal to operand0
        cb.require_equal(
            "local_index(0) == aux0(0)",
            step_curr.local_index.expr(),
            step_curr.aux0.expr(),
        );
        cb.first_row(|cb| {
            cb.require_zero("local_sub_index(0) == 0", step_curr.local_sub_index.expr());
        });
        // TODO: local_read_value_version(0) < clk(0);
        cb.require_true(
            "local_write_value_invalid(0) == true",
            step_curr.local_write_value_invalid.expr(),
        );
        cb.require_equal(
            "local_write_value_header(0) == local_read_value_header(0)",
            step_curr.local_write_value_header.expr(),
            step_curr.local_read_value_header.expr(),
        );
        cb.require_equal(
            "local_write_version == clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_state_transition(vec![(SP, Transition::Same)]);
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

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::StoreLocStage2);
        });
        Self {
            local_value_header: header,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StoreLocStage2<F> {
    stack_value_header: ValueHeader<F>,
}

impl<F: Field> InstructionGadgetV2<F> for StoreLocStage2<F> {
    const NAME: &'static str = "StoreLoc_Stage2";
    const OPCODE: Opcode = Opcode::StLoc;
    const EXECUTION_STATE: ExecutionState = ExecutionState::StoreLocStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::StoreLocStage1);
        });

        let value_len = cb.query_u16();
        let value_flen = cb.query_u16();
        let header = ValueHeader::pair(value_len.expr(), value_flen.expr());

        let step_curr = cb.curr.state.clone();

        cb.require_no_stack_push();
        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.first_row(|cb| {
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                step_curr.stack_pop_sub_index.expr(),
            );
        });

        cb.first_row(|cb| {
            cb.condition(step_curr.stack_pop_value_header.expr(), |cb| {
                cb.require_equal(
                    "(len, flen) = stack_pop_value(0)",
                    step_curr.stack_pop_value.expr(),
                    header.expr(),
                );
                cb.require_equal(
                    "step_counter(0) == flen",
                    step_curr.step_counter.expr(),
                    value_flen.expr(),
                );
            });
            cb.condition(
                1u64.expr() - step_curr.stack_pop_value_header.expr(),
                |cb| {
                    cb.require_equal(
                        "step_counter(0) == 1",
                        step_curr.step_counter.expr(),
                        1u64.expr(),
                    );
                },
            );
        });
        // TODO: stack_pop_version(0) < clk(0);
        cb.require_equal(
            "local_frame_index(0) == frame_index(0)",
            step_curr.local_frame_index.expr(),
            step_curr.frame_index.expr(),
        );
        // ensure local_index equal to operand0
        cb.require_equal(
            "local_index(0) == aux0(0)",
            step_curr.local_index.expr(),
            step_curr.aux0.expr(),
        );
        cb.require_equal(
            "local_sub_index(0) == stack_pop_sub_index(0)",
            step_curr.local_sub_index.expr(),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_true(
            "local_read_value_invalid(0) == true",
            step_curr.local_read_value_invalid.expr(),
        );
        // TODO:local_read_value_version(0) < clk(0)
        cb.require_equal(
            "local_write_value(0) == stack_pop_value(0)",
            step_curr.local_write_value.expr(),
            step_curr.stack_pop_value.expr(),
        );
        cb.require_equal(
            "local_write_value_header(0) == stack_pop_value_header(0)",
            step_curr.local_write_value_header.expr(),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_zero(
            "local_write_value(0) != INVALID",
            step_curr.local_write_value_invalid.expr(),
        );
        cb.require_equal(
            "local_write_version == clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );

        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });
        cb.last_row(|cb| {
            cb.require_state_transition(
                [FRAME_INDEX, MODULE_INDEX, FUNCTION_INDEX]
                    .into_iter()
                    .map(|s| (s, Transition::Same))
                    .chain(vec![
                        (PC, Transition::Delta(1.expr())),
                        (SP, Transition::Delta((-1).expr())),
                    ])
                    .collect(),
            );
        });

        Self {
            stack_value_header: header,
        }
    }
}
