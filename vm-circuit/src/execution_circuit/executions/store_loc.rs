use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::step::{OPCODE, OPERAND0, OPERAND1, PC, SP};
use crate::execution_circuit::InstructionGadgetV2;
use crate::utils::vm_constraint_builder::{Transition, VmConstraintBuilder};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use field_exts::Field;
use std::marker::PhantomData;
use util::Expr;

#[derive(Clone, Debug)]
pub struct StoreLocStage1<F> {
    phantom_data: PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for StoreLocStage1<F> {
    const NAME: &'static str = "StoreLoc_Stage1";
    const EXECUTION_STATE: ExecutionState = ExecutionState::StoreLocStage1;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        let step_curr = cb.curr.state.clone();

        cb.require_no_stack_pop();
        cb.require_no_stack_push();

        cb.require_in_set(
            format!("{}, opcode in OPCODES", Self::NAME),
            step_curr.opcode.expr(),
            Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
        );

        cb.first_row(|cb| {
            cb.condition(1.expr() - step_curr.local_read_value_invalid.expr(), |cb| {
                cb.condition(step_curr.local_read_value_header.expr(), |cb| {
                    cb.require_equal(
                        format!(
                            "{}, step_counter(0) == local_read_value(0).as_header().flen",
                            Self::NAME
                        ),
                        step_curr.step_counter.expr(),
                        step_curr.local_read_value.as_header().flen(),
                    );
                });
                cb.condition(
                    1u64.expr() - step_curr.local_read_value_header.expr(),
                    |cb| {
                        cb.require_equal(
                            format!("{}, step_counter(0) == 1", Self::NAME),
                            step_curr.step_counter.expr(),
                            1u64.expr(),
                        );
                    },
                );
            });
        });
        cb.require_equal(
            format!("{}, local_frame_index(0) == frame_index(0)", Self::NAME),
            step_curr.local_frame_index.expr(),
            step_curr.frame_index.expr(),
        );
        // ensure local_index equal to operand0
        cb.require_equal(
            format!("{}, local_index(0) == operand0(0)", Self::NAME),
            step_curr.local_index.expr(),
            step_curr.operand0.expr(),
        );
        cb.first_row(|cb| {
            cb.require_zero(
                format!("{}, local_sub_index(0) == 0", Self::NAME),
                step_curr.local_sub_index.expr(),
            );
        });
        cb.require_true(
            format!("{}, local_write_value_invalid(0) == true", Self::NAME),
            step_curr.local_write_value_invalid.expr(),
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
        cb.last_row(|cb| {
            cb.require_state_transition(
                [PC, OPCODE, OPERAND0, OPERAND1]
                    .into_iter()
                    .map(|s| (s, Transition::Same))
                    .collect(),
            );
        });

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::StoreLocStage2);
        });
        Self {
            phantom_data: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StoreLocStage2<F> {
    phantom_data: PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for StoreLocStage2<F> {
    const NAME: &'static str = "StoreLoc_Stage2";
    const EXECUTION_STATE: ExecutionState = ExecutionState::StoreLocStage2;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::StoreLocStage1);
        });

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
                    format!(
                        "{}, step_counter(0) == stack_pop_value(0).as_header().flen",
                        Self::NAME
                    ),
                    step_curr.step_counter.expr(),
                    step_curr.stack_pop_value.as_header().flen(),
                );
            });
            cb.condition(
                1u64.expr() - step_curr.stack_pop_value_header.expr(),
                |cb| {
                    cb.require_equal(
                        format!("{}, step_counter(0) == 1", Self::NAME),
                        step_curr.step_counter.expr(),
                        1u64.expr(),
                    );
                },
            );
        });
        cb.require_equal(
            format!("{}, local_frame_index(0) == frame_index(0)", Self::NAME),
            step_curr.local_frame_index.expr(),
            step_curr.frame_index.expr(),
        );
        // ensure local_index equal to operand0
        cb.require_equal(
            format!("{}, local_index(0) == operand0(0)", Self::NAME),
            step_curr.local_index.expr(),
            step_curr.operand0.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_sub_index(0) == stack_pop_sub_index(0)",
                Self::NAME
            ),
            step_curr.local_sub_index.expr(),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_true(
            format!("{}, local_read_value_invalid(0) == true", Self::NAME),
            step_curr.local_read_value_invalid.expr(),
        );
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
        cb.require_zero(
            format!("{}, local_write_value(0) != INVALID", Self::NAME),
            step_curr.local_write_value_invalid.expr(),
        );
        cb.require_equal(
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );

        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![
                (PC, Transition::Delta(1.expr())),
                (SP, Transition::Delta((-1).expr())),
            ]);
        });

        Self {
            phantom_data: PhantomData,
        }
    }
}
