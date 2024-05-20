use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::ValueHeader;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use types::Field;

#[derive(Clone, Debug)]
pub struct VecLen<F> {
    value_header: ValueHeader<F>,
}

impl<F: Field> InstructionGadgetV2<F> for VecLen<F> {
    const NAME: &'static str = "VecLen";
    const OPCODE: Opcode = Opcode::VecLen;
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecLen;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let value_header = ValueHeader::new(cb);
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );
            cb.require_equal(
                format!("{}, step_counter(0) == 4", Self::NAME),
                step_curr.step_counter.expr(),
                4u64.expr(),
            );
        });
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
        cb.require_state_transition(vec![(SP, Transition::Same)]);

        cb.not_last_row(|cb| {
            cb.require_no_stack_push();
            cb.require_no_local_op();
        });

        cb.last_row(|cb| {
            // read vec header
            let local_frame_index = cb.cell_at_offset(&step_curr.stack_pop_value, -2).expr();
            cb.require_equal(
                format!(
                    "{}, local_frame_index(0) == stack_pop_value(-2)",
                    Self::NAME
                ),
                step_curr.local_frame_index.expr(),
                local_frame_index,
            );
            let local_index = cb.cell_at_offset(&step_curr.stack_pop_value, -1).expr();
            cb.require_equal(
                format!("{}, local_index(0) == stack_pop_value(-1)", Self::NAME),
                step_curr.local_index.expr(),
                local_index,
            );
            cb.require_equal(
                format!("{}, local_sub_index(0) == stack_pop_value(0)", Self::NAME),
                step_curr.local_sub_index.expr(),
                step_curr.stack_pop_value.expr(),
            );
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
            cb.require_true(
                format!("{}, local_read_value_header(0)", Self::NAME),
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
            // TODO: local_read_version(0) < clk(0);
            cb.require_equal(
                format!("{}, local_write_version(0) == clk(0)", Self::NAME),
                step_curr.local_write_version.expr(),
                step_curr.clk.expr(),
            );

            // push length
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );
            cb.require_equal(
                format!("{}, local_read_value(0) == value_header", Self::NAME),
                step_curr.local_read_value.expr(),
                value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_value(0) == value_header.len", Self::NAME),
                step_curr.stack_push_value.expr(),
                value_header.len.clone(),
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
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        VecLen { value_header }
    }
}
