use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::SubIndexGadget;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use types::Field;

#[derive(Clone, Debug)]
pub struct BorrowField<const MUTABLE: bool, F: Field> {
    sub_index_gadget: Option<SubIndexGadget<F, 8>>,
}
impl<const MUTABLE: bool, F: Field> InstructionGadgetV2<F> for BorrowField<MUTABLE, F> {
    const NAME: &'static str = "BorrowField";

    const OPCODE: Opcode = if MUTABLE {
        Opcode::MutBorrowField
    } else {
        Opcode::ImmBorrowField
    };
    const EXECUTION_STATE: ExecutionState = if MUTABLE {
        ExecutionState::MutBorrowField
    } else {
        ExecutionState::ImmBorrowField
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let mut sub_index_gadget = None;
        let next_row_state = cb.step_state_at_offset(1);
        cb.first_row(|cb| {
            cb.require_equal(
                format!("{}, step_counter(0) == 4", Self::NAME),
                cb.curr.state.step_counter.expr(),
                4u64.expr(),
            );
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                cb.curr.state.stack_pop_sub_index.expr(),
            );
            cb.require_true(
                format!("{}, stack_push_value_header(0) == true", Self::NAME),
                cb.curr.state.stack_push_value_header.expr(),
            );
        });
        cb.not_first_row(|cb| {
            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                cb.curr.state.stack_push_value_header.expr(),
            );
        });

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            cb.curr.state.stack_pop_index.expr(),
            cb.curr.state.sp.expr(),
        );

        //TODO: stack_pop_version(0) < clk(0);

        cb.require_equal(
            format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
            cb.curr.state.stack_push_index.expr(),
            cb.curr.state.sp.expr(),
        );
        cb.require_equal(
            format!(
                "{}, stack_push_sub_index(0) == stack_pop_sub_index(0)",
                Self::NAME
            ),
            cb.curr.state.stack_push_sub_index.expr(),
            cb.curr.state.stack_pop_sub_index.expr(),
        );
        cb.require_equal(
            format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
            cb.curr.state.stack_push_version.expr(),
            cb.curr.state.clk.expr(),
        );
        cb.require_state_transition(vec![(SP, Transition::Same)]);

        //TODO: super::common::fake_local_read_zero(0);

        cb.not_last_row(|cb| {
            cb.require_equal(
                format!("{}, stack_pop_value(0) == stack_push_value(0)", Self::NAME),
                cb.curr.state.stack_pop_value.expr(),
                cb.curr.state.stack_push_value.expr(),
            );
            cb.require_equal(
                format!(
                    "{}, stack_pop_sub_index(1) == stack_pop_sub_index(0) + 1",
                    Self::NAME
                ),
                next_row_state.stack_pop_sub_index.expr(),
                cb.curr.state.stack_pop_sub_index.expr() + 1u64.expr(),
            );
        });

        cb.last_row(|cb| {
            sub_index_gadget = Some(SubIndexGadget::construct(
                cb,
                cb.curr.state.stack_pop_value.expr(),
                cb.curr.state.aux0.expr() + 1u64.expr(),
                cb.curr.state.stack_push_value.expr(),
                Self::NAME,
            ));

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        BorrowField { sub_index_gadget }
    }
}
