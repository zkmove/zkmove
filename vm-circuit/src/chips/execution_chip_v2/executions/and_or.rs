use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use gadgets::util::{and, or};
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct AndOr<F, const AND: bool> {
    phantom_data: PhantomData<F>,
}
impl<F: Field, const AND: bool> InstructionGadgetV2<F> for AndOr<F, AND> {
    const NAME: &'static str = if AND { "And" } else { "Or" };

    const OPCODE: Opcode = if AND { Opcode::And } else { Opcode::Or };
    const EXECUTION_STATE: ExecutionState = if AND {
        ExecutionState::And
    } else {
        ExecutionState::Or
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );
            cb.require_equal(
                "step_counter(0) == 2",
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
        });

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_boolean(
            "stack_pop_value(0) == 0 | 1",
            step_curr.stack_pop_value.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_value_header(0) == false", Self::NAME),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_no_local_op();

        cb.last_row(|cb| {
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );
            let stack_pop_value_prev = cb.cell_at_offset(&step_curr.stack_pop_value, -1).expr();
            let expected = if AND {
                and::expr([stack_pop_value_prev, step_curr.stack_pop_value.expr()])
            } else {
                or::expr([stack_pop_value_prev, step_curr.stack_pop_value.expr()])
            };
            cb.require_equal(
                format!("{}, stack_push_value(0) == expected", Self::NAME),
                step_curr.stack_push_value.expr(),
                expected,
            );
            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                step_curr.stack_push_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        AndOr {
            phantom_data: PhantomData,
        }
    }
}
