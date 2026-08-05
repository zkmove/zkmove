use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::step::{PC, SP};
use crate::execution_circuit::InstructionGadgetV2;
use crate::utils::vm_constraint_builder::{Transition, VmConstraintBuilder};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use field_exts::util::Expr;
use field_exts::Field;
use std::marker::PhantomData;

#[derive(Clone, Debug, Default)]
pub struct MoveOrCopyLoc<F, const MOVE: bool>(PhantomData<F>);
impl<F: Field, const MOVE: bool> InstructionGadgetV2<F> for MoveOrCopyLoc<F, MOVE> {
    const NAME: &'static str = if MOVE { "MoveLoc" } else { "CopyLoc" };
    const EXECUTION_STATE: ExecutionState = if MOVE {
        ExecutionState::MoveLoc
    } else {
        ExecutionState::CopyLoc
    };

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_in_set(
                format!("{}, opcode in OPCODES", Self::NAME),
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.condition(step_curr.stack_push_value_header.expr(), |cb| {
                cb.require_equal(
                    format!(
                        "{}, step_counter(0) == stack_push_value(0).as_header().flen",
                        Self::NAME
                    ),
                    step_curr.step_counter.expr(),
                    step_curr.stack_push_value.as_header().flen(),
                );
            });
            cb.condition(
                1u64.expr() - step_curr.stack_push_value_header.expr(),
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
            format!("{}, stack_push_index(0) == sp(0)+1", Self::NAME),
            step_curr.stack_push_index.expr(),
            step_curr.sp.expr() + 1u64.expr(),
        );
        cb.require_equal(
            format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
            step_curr.stack_push_version.expr(),
            step_curr.clk.expr(),
        );
        cb.first_row(|cb| {
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );
        });

        cb.require_no_stack_pop();

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
                "{}, local_sub_index(0) == stack_push_sub_index(0)",
                Self::NAME
            ),
            step_curr.local_sub_index.expr(),
            step_curr.stack_push_sub_index.expr(),
        );
        cb.require_zero(
            format!("{}, lcoal_read_value(0) != INVALID", Self::NAME),
            step_curr.local_read_value_invalid.expr(),
        );
        cb.require_equal(
            format!("{}, local_read_value(0) == stack_push_value(0)", Self::NAME),
            step_curr.local_read_value.expr(),
            step_curr.stack_push_value.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_read_value_header(0) == stack_push_value_header(0)",
                Self::NAME
            ),
            step_curr.local_read_value_header.expr(),
            step_curr.stack_push_value_header.expr(),
        );
        if MOVE {
            cb.require_true(
                format!("{}, local_write_value(0) == INVALID", Self::NAME),
                step_curr.local_write_value_invalid.expr(),
            );
        } else {
            cb.require_equal(
                format!(
                    "{}, local_write_value(0) == local_read_value(0)",
                    Self::NAME
                ),
                step_curr.local_write_value.expr(),
                step_curr.local_read_value.expr(),
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
                format!(
                    "{}, local_write_value_invalid(0) == local_read_value_invalid(0)",
                    Self::NAME
                ),
                step_curr.local_write_value_invalid.expr(),
                step_curr.local_read_value_invalid.expr(),
            );
        }
        cb.require_equal(
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );

        cb.last_row(|cb| {
            cb.require_state_transition(vec![
                (PC, Transition::Delta(1.expr())),
                (SP, Transition::Delta(1.expr())),
            ]);
        });

        Self::default()
    }
}
