use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::ExtendedSubIndex;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::value::Index;
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use types::Field;

#[derive(Clone, Debug)]
pub struct ReadRef<F: Field> {
    header_sub_index: Cell<F>,
    header_sub_index_ext: ExtendedSubIndex<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for ReadRef<F> {
    const NAME: &'static str = "ReadRef";
    const OPCODE: Opcode = Opcode::ReadRef;
    const EXECUTION_STATE: ExecutionState = ExecutionState::ReadRef;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_sub_index = cb.query_cell();
        let header_sub_index_ext =
            ExtendedSubIndex::<_, 8>::construct(cb, "header_sub_index", header_sub_index.expr());
        let step_curr = cb.curr.state.clone();
        let step_next = cb.step_state_at_offset(1);

        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
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
            let index = Index::new(step_curr.local_frame_index.expr(), step_curr.local_index.expr());
            cb.require_equal(
                format!("{}, (local_frame_index(0), local_index(0)) == stack_pop_value(0).index", Self::NAME),
                index.expr(),
                step_curr.stack_pop_value.as_reference().index(),
            );
            cb.require_equal(
                format!("{}, local_sub_index(0) == stack_pop_value(0).sub_index", Self::NAME),
                step_curr.local_sub_index.expr(),
                step_curr.stack_pop_value.as_reference().sub_index(),
            );

            //if !local_read_value_header(0) { step_counter(0) == 1; }
            cb.require_zero(
                format!(
                    "{}, (1 - local_read_value_header(0)) * (step_counter(0) - 1) == 0",
                    Self::NAME
                ),
                (1u64.expr() - step_curr.local_read_value_header.expr())
                    * (step_curr.step_counter.expr() - 1u64.expr()),
            );
            //if local_read_value_header(0) { step_counter(0) == local_read_value(0).f_len; }
            cb.require_zero(
                format!(
                    "{}, local_read_value_header(0) * (step_counter(0) - local_read_value(0).flen) == 0",
                    Self::NAME
                ),
                step_curr.local_read_value_header.expr()
                    * (step_curr.step_counter.expr() - step_curr.local_read_value.as_header().flen()),
            );
            // record the sub index of the referenced value's header
            cb.require_equal(
                format!("{}, header_sub_index(0) == local_sub_index(0)", Self::NAME),
                header_sub_index.expr(),
                step_curr.local_sub_index.expr(),
            );
        });
        cb.not_first_row(|cb| {
            cb.require_no_stack_pop();
        });

        cb.require_equal(
            format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
            step_curr.stack_push_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_equal(
            format!("{}, local_sub_index(0) == concat(header_sub_index(0), nonzero(stack_push_sub_index(0)))" , Self::NAME),
            step_curr.local_sub_index.expr(),
            header_sub_index_ext.concat_sub_index(step_curr.stack_push_sub_index.expr()),
        );
        cb.require_equal(
            format!("{}, stack_push_value(0) == local_read_value(0)", Self::NAME),
            step_curr.stack_push_value.expr(),
            step_curr.local_read_value.expr(),
        );
        cb.require_equal(
            format!(
                "{}, stack_push_value_header(0) == local_read_value_header(0)",
                Self::NAME
            ),
            step_curr.stack_push_value_header.expr(),
            step_curr.local_read_value_header.expr(),
        );
        cb.require_equal(
            format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
            step_curr.stack_push_version.expr(),
            step_curr.clk.expr(),
        );
        //TODO: local_read_version(0) < clk(0);

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
                "{}, local_write_value_invalid(0) == local_read_value_invalid(0)",
                Self::NAME
            ),
            step_curr.local_write_value_invalid.expr(),
            step_curr.local_read_value_invalid.expr(),
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
        cb.not_last_row(|cb| {
            cb.require_equal(
                format!(
                    "{}, local_frame_index(1) == local_frame_index(0)",
                    Self::NAME
                ),
                step_next.local_frame_index.expr(),
                step_curr.local_frame_index.expr(),
            );
            cb.require_equal(
                format!("{}, local_index(1) == local_index(0)", Self::NAME),
                step_next.local_index.expr(),
                step_curr.local_index.expr(),
            );
            let header_sub_index_next = cb.cell_at_offset(&header_sub_index, 1).expr();
            cb.require_equal(
                format!("{}, header_sub_index(1) == header_sub_index(0)", Self::NAME),
                header_sub_index_next,
                header_sub_index.expr(),
            );
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        ReadRef {
            header_sub_index,
            header_sub_index_ext,
        }
    }
}
