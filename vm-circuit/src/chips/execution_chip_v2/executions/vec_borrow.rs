use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::ExtendedSubIndex;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use types::Field;

#[derive(Clone, Debug)]
pub struct VecBorrow<const MUTABLE: bool, F: Field> {
    vec_ref_sub_index: ExtendedSubIndex<F, 8>,
}

impl<const MUTABLE: bool, F: Field> InstructionGadgetV2<F> for VecBorrow<MUTABLE, F> {
    const NAME: &'static str = "VecBorrow";
    const OPCODE: Opcode = if MUTABLE {
        Opcode::VecMutBorrow
    } else {
        Opcode::VecImmBorrow
    };
    const EXECUTION_STATE: ExecutionState = if MUTABLE {
        ExecutionState::VecMutBorrow
    } else {
        ExecutionState::VecImmBorrow
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let vec_ref_sub_index =
            ExtendedSubIndex::<_, 8>::construct(cb, Self::NAME, step_curr.stack_pop_value.expr());

        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );
            cb.require_equal(
                format!("{}, step_counter(0) == 5", Self::NAME),
                step_curr.step_counter.expr(),
                5u64.expr(),
            );
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr(),
            );
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                step_curr.stack_pop_sub_index.expr(),
            );
            cb.require_zero(
                format!("{}, stack_pop_value_header(0) == false", Self::NAME),
                step_curr.stack_pop_value_header.expr(),
            );
            cb.require_no_stack_push();
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
        });

        cb.not_first_row(|cb| {
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
            cb.require_equal(
                format!("{}, stack_push_index(0) == stack_pop_index(0)", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.stack_pop_index.expr(),
            );
            cb.require_equal(
                format!(
                    "{}, stack_push_sub_index(0) == stack_pop_sub_index(0)",
                    Self::NAME
                ),
                step_curr.stack_push_sub_index.expr(),
                step_curr.stack_pop_sub_index.expr(),
            );
            cb.not_last_row(|cb| {
                cb.require_equal(
                    format!("{}, stack_push_value(0) == stack_pop_value(0)", Self::NAME),
                    step_curr.stack_push_value.expr(),
                    step_curr.stack_pop_value.expr(),
                );
            });
            cb.require_equal(
                format!(
                    "{}, stack_push_value_header(0) == stack_pop_value_header(0)",
                    Self::NAME
                ),
                step_curr.stack_push_value_header.expr(),
                step_curr.stack_pop_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) = clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

        cb.require_no_local_op();

        cb.last_row(|cb| {
            //push back the last row of the new reference
            let index = cb.cell_at_offset(&step_curr.stack_pop_value, -4).expr();
            cb.require_equal(
                format!(
                    "{}, stack_push_value(0) == stack_pop_value(0).concat(index)",
                    Self::NAME
                ),
                step_curr.stack_push_value.expr(),
                vec_ref_sub_index.concat_sub_index(index),
            );

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        VecBorrow { vec_ref_sub_index }
    }
}
