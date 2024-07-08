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
        let step_prev = cb.step_state_at_offset(-1);
        let vec_ref_sub_index = ExtendedSubIndex::<_, 8>::construct(
            cb,
            Self::NAME,
            step_curr.stack_pop_value.as_reference().sub_index(),
        );

        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );
            cb.require_equal(
                format!("{}, step_counter(0) == 2", Self::NAME),
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr(),
            );
        });

        cb.require_zero(
            format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_value_header(0) == false", Self::NAME),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_no_local_op();

        cb.last_row(|cb| {
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );
            cb.require_equal(
                format!(
                    "{}, stack_push_value(0).as_reference().index == stack_pop_value(0).as_reference().index",
                    Self::NAME
                ),
                step_curr.stack_push_value.as_reference().index(),
                step_curr.stack_pop_value.as_reference().index(),
            );
            let popped_index = step_prev.stack_pop_value.as_integer().lo();
            cb.require_equal(
                format!(
                    "{}, stack_push_value(0).as_reference().sub_index == stack_pop_value(0).as_reference().sub_index.concat(popped_index + 1)",
                    Self::NAME
                ),
                step_curr.stack_push_value.as_reference().sub_index(),
                vec_ref_sub_index.concat_sub_index(popped_index),
            );
            cb.require_equal(
                format!("{}, stack_push_value_header(0) == stack_pop_value_header(0)", Self::NAME),
                step_curr.stack_push_value_header.expr(),
                step_curr.stack_pop_value_header.expr(),
            );
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Delta(1.expr())),
                (SP, Transition::Delta((-1).expr())),
            ]);
        });

        VecBorrow { vec_ref_sub_index }
    }
}
