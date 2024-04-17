use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ValueHeader;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use crate::witness::exec_step::ValueFlag;
use gadgets::util::{and, not};
use types::Field;

#[derive(Clone, Debug)]
pub struct Pack<F> {
    header: ValueHeader<F>,
    field_index: Cell<F>,
    field_counter: Cell<F>,
}
impl<F: Field> InstructionGadgetV2<F> for Pack<F> {
    const NAME: &'static str = "Pack";

    const OPCODE: Opcode = Opcode::Pack;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header = ValueHeader::new(cb);
        let field_index = cb.query_cell();
        let field_index_next = cb.cell_at_offset(&field_index, 1);
        let field_counter = cb.query_cell();
        let field_counter_next = cb.cell_at_offset(&field_counter, 1);

        cb.first_row(|cb| {
            let flen = cb.curr.state.step_counter.expr(); //flen is equal to step_counter(0)
            let num_field = cb.curr.state.aux0.expr();

            cb.require_equal(
                format!(
                    "{}, stack_push_index(0) == sp(0) - num_field + 1",
                    Self::NAME
                ),
                cb.curr.state.stack_push_index.expr(),
                cb.curr.state.sp.expr() - num_field.clone() + 1u64.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                cb.curr.state.stack_push_sub_index.expr(),
            );
            let value_header = ValueHeader::pair(num_field, flen);
            cb.require_equal(
                format!("{}, stack_push_value(0) == (num_field, flen)", Self::NAME),
                cb.curr.state.stack_push_value.expr(),
                value_header.expr(),
            );
            cb.require_equal(
                format!(
                    "{}, stack_push_value_flag(0) == ValueFlag::Header",
                    Self::NAME
                ),
                cb.curr.state.stack_push_value_flag.expr(),
                ValueFlag::Header.to_u64().expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                cb.curr.state.stack_push_version.expr(),
                cb.curr.state.clk.expr(),
            );

            //TODO: super::common::fake_empty_stack_pop(0);
            //TODO: super::common::fake_local_read_zero(0);

            cb.require_equal(
                format!("{}, field_index(1) == aux0(0)", Self::NAME),
                field_index_next.expr(),
                cb.curr.state.aux0.expr(),
            );
            cb.require_equal(
                format!("{}, stack_pop_index(1) == sp(0)", Self::NAME),
                cb.next.state.stack_pop_index.expr(),
                cb.curr.state.sp.expr(),
            );
            cb.require_zero(
                format!("{}, stack_pop_sub_index(1) == 0", Self::NAME),
                cb.next.state.stack_pop_sub_index.expr(),
            );

            //TODO: stack_pop_version(1) < clk(0);
        });

        cb.not_first_row(|cb| {
            let is_simple = and::expr([
                not::expr(cb.curr.state.stack_pop_sub_index.expr()),
                not::expr(
                    cb.curr.state.stack_pop_value_flag.expr() - ValueFlag::Simple.to_u64().expr(),
                ),
            ]);
            let is_header = and::expr([
                not::expr(cb.curr.state.stack_pop_sub_index.expr()),
                not::expr(
                    cb.curr.state.stack_pop_value_flag.expr() - ValueFlag::Header.to_u64().expr(),
                ),
            ]);

            //if is_simple then 'field_counter(0)' must equal to 1
            cb.require_zero(
                format!("{}, is_simple * (field_counter(0) - 1)", Self::NAME),
                is_simple * (field_counter.expr() - 1u64.expr()),
            );

            //if is_header then 'field_counter(0)' must equal to 'stack_pop_value(0).flen'
            cb.require_equal(
                format!("{}, stack_pop_value(0) == header", Self::NAME),
                cb.curr.state.stack_pop_value.expr(),
                header.expr(),
            );
            cb.require_zero(
                format!(
                    "{}, is_header * (field_counter(0) - header.flen) == 0",
                    Self::NAME
                ),
                is_header * (field_counter.expr() - header.flen.expr()),
            );

            cb.require_equal(
                format!("{}, stack_push_value(0) == stack_pop_value(0)", Self::NAME),
                cb.curr.state.stack_push_value.expr(),
                cb.curr.state.stack_pop_value.expr(),
            );
            cb.require_equal(
                format!(
                    "{}, stack_push_value_flag(0) == stack_pop_value_flag(0)",
                    Self::NAME
                ),
                cb.curr.state.stack_push_value_flag.expr(),
                cb.curr.state.stack_pop_value_flag.expr(),
            );

            //TODO: field_index < 2^16;

            cb.require_equal(
                format!(
                    "{}, stack_push_sub_index(0) == stack_pop_sub_index(0) << 16 + field_index(0)",
                    Self::NAME
                ),
                cb.curr.state.stack_push_sub_index.expr(),
                cb.curr.state.stack_pop_sub_index.expr() * 2u64.pow(16).expr() + field_index.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                cb.curr.state.stack_push_version.expr(),
                cb.curr.state.clk.expr(),
            );

            //TODO: super::common::fake_local_read_zero(0);

            let end_of_one_field = and::expr([
                not::expr(cb.next.state.clk.expr() - cb.curr.state.clk.expr()), //not last row
                not::expr(field_counter.expr() - 1u64.expr()), //field_counter(0) == 1
            ]);
            cb.condition(end_of_one_field.clone(), |cb| {
                cb.require_equal(
                    format!("{}, field_index(1) == field_index(0) - 1", Self::NAME),
                    field_index_next.expr(),
                    field_index.expr() - 1u64.expr(),
                );
                cb.require_equal(
                    format!(
                        "{}, stack_pop_index(1) == stack_pop_index(0) - 1",
                        Self::NAME
                    ),
                    cb.next.state.stack_pop_index.expr(),
                    cb.curr.state.stack_pop_index.expr() - 1u64.expr(),
                );
                cb.require_zero(
                    format!("{}, stack_pop_sub_index(1) == 0", Self::NAME),
                    cb.next.state.stack_pop_sub_index.expr(),
                );

                //TODO: stack_pop_version(1) < clk(0);
            });

            cb.condition(not::expr(end_of_one_field), |cb| {
                cb.require_equal(
                    format!("{}, field_index(1) == field_index(0)", Self::NAME),
                    field_index_next.expr(),
                    field_index.expr(),
                );
                cb.require_equal(
                    format!("{}, stack_pop_index(1) == stack_pop_index(0)", Self::NAME),
                    cb.next.state.stack_pop_index.expr(),
                    cb.curr.state.stack_pop_index.expr(),
                );
                cb.require_equal(
                    format!(
                        "{}, stack_pop_version(1) == stack_pop_version(0)",
                        Self::NAME
                    ),
                    cb.next.state.stack_pop_version.expr(),
                    cb.curr.state.stack_pop_version.expr(),
                );
                cb.require_equal(
                    format!("{}, field_counter(1) == field_counter(0) - 1", Self::NAME),
                    field_counter_next.expr(),
                    field_counter.expr() - 1u64.expr(),
                );
            });
        });

        cb.not_last_row(|cb| {
            cb.require_equal(
                format!("{}, stack_push_index(1) == stack_push_index(0)", Self::NAME),
                cb.next.state.stack_push_index.expr(),
                cb.curr.state.stack_push_index.expr(),
            );
            cb.require_equal(
                format!("{}, step_counter(1) == step_counter(0) - 1", Self::NAME),
                cb.next.state.step_counter.expr(),
                cb.curr.state.step_counter.expr() - 1u64.expr(),
            );
            cb.require_equal(
                format!("{}, sp(1) == sp(0)", Self::NAME),
                cb.next.state.sp.expr(),
                cb.curr.state.sp.expr(),
            );
        });

        cb.last_row(|cb| {
            // all fields processed
            cb.require_equal(
                format!("{}, field_index(0) == 1", Self::NAME),
                field_index.expr(),
                1u64.expr(),
            );
            cb.require_equal(
                format!("{}, field_counter(0) == 1", Self::NAME),
                field_counter.expr(),
                1u64.expr(),
            );

            cb.require_equal(
                format!("{}, sp(1) == stack_push_index(0)", Self::NAME),
                cb.next.state.sp.expr(),
                cb.curr.state.stack_push_index.expr(),
            );
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        Pack {
            header,
            field_index,
            field_counter,
        }
    }
}
