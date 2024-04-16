use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::witness::exec_step::ValueFlag;
use movelang::flattened_value::ValueHeader;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct BorrowLoc<const MUTABLE: bool, F> {
    phantom_data: PhantomData<F>,
}
impl<const MUTABLE: bool, F: Field> InstructionGadgetV2<F> for BorrowLoc<MUTABLE, F> {
    const NAME: &'static str = "BorrowLoc";

    const OPCODE: Opcode = if MUTABLE {
        Opcode::MutBorrowLoc
    } else {
        Opcode::ImmBorrowLoc
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.first_row(|cb| {
            // TODO: add bytecode lookup

            cb.require_equal(
                format!("{}, step_counter(0) == 4", Self::NAME),
                cb.curr.state.step_counter.expr(),
                4u64.expr(),
            );

            cb.require_equal(
                format!("{}, stack_push_value(0) == (3,4)", Self::NAME),
                cb.curr.state.stack_push_value.expr(),
                ValueHeader::default_for_ref_value().expr(),
            );

            cb.require_equal(
                format!(
                    "{}, stack_push_value_flag(0) == ValueFlag::Header",
                    Self::NAME
                ),
                cb.curr.state.stack_push_value_flag.expr(),
                ValueFlag::Header.to_u64().expr(),
            );

            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                cb.curr.state.stack_push_sub_index.expr(),
            );

            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0) + 1", Self::NAME),
                cb.curr.state.stack_push_index.expr(),
                cb.curr.state.sp.expr() + 1u64.expr(),
            );

            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                cb.curr.state.stack_push_version.expr(),
                cb.curr.state.clk.expr(),
            );

            //TODO: super::common::fake_empty_stack_pop(0);
            //TODO: super::common::fake_local_read_zero(0);
        });

        cb.not_first_row(|cb| {
            //step_counter(0) == 3
            cb.condition(cb.curr.state.step_counter.expr() - 3u64.expr(), |cb| {
                cb.require_equal(
                    format!("{}, stack_push_value(0) = frame_index(0)", Self::NAME),
                    cb.curr.state.stack_push_value.expr(),
                    cb.curr.state.frame_index.expr(),
                );

                cb.require_equal(
                    format!("{}, stack_push_sub_index(0) == 1", Self::NAME),
                    cb.curr.state.stack_push_sub_index.expr(),
                    1u64.expr(),
                );
            });

            //step_counter(0) == 2
            cb.condition(cb.curr.state.step_counter.expr() - 2u64.expr(), |cb| {
                cb.require_equal(
                    format!("{}, stack_push_value(0) = aux0(0)", Self::NAME),
                    cb.curr.state.stack_push_value.expr(),
                    cb.curr.state.aux0.expr(),
                );
                cb.require_equal(
                    format!(
                        "{}, stack_push_value_flag(0) == ValueFlag::Simple",
                        Self::NAME
                    ),
                    cb.curr.state.stack_push_value_flag.expr(),
                    ValueFlag::Simple.to_u64().expr(),
                );

                cb.require_equal(
                    format!("{}, stack_push_sub_index(0) == 2", Self::NAME),
                    cb.curr.state.stack_push_sub_index.expr(),
                    2u64.expr(),
                );
            });

            //step_counter(0) == 1
            cb.condition(cb.curr.state.step_counter.expr() - 2u64.expr(), |cb| {
                cb.require_zero(
                    format!("{}, stack_push_value(0) = 0", Self::NAME),
                    cb.curr.state.stack_push_value.expr(),
                );
                cb.require_equal(
                    format!(
                        "{}, stack_push_value_flag(0) == ValueFlag::Simple",
                        Self::NAME
                    ),
                    cb.curr.state.stack_push_value_flag.expr(),
                    ValueFlag::Simple.to_u64().expr(),
                );

                cb.require_equal(
                    format!("{}, stack_push_sub_index(0) == 3", Self::NAME),
                    cb.curr.state.stack_push_sub_index.expr(),
                    3u64.expr(),
                );
            });

            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0) + 1", Self::NAME),
                cb.curr.state.stack_push_index.expr(),
                cb.curr.state.sp.expr() + 1u64.expr(),
            );

            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                cb.curr.state.stack_push_version.expr(),
                cb.curr.state.clk.expr(),
            );

            //TODO: super::common::fake_empty_stack_pop(0);
            //TODO: super::common::fake_local_read_zero(0);
        });

        cb.not_last_row(|cb| {
            cb.require_equal(
                format!("{}, sp(1) == sp(0)", Self::NAME),
                cb.next.state.sp.expr(),
                cb.curr.state.sp.expr(),
            );
            //TODO: add common constraints for aux0,aux1
            cb.require_equal(
                format!("{}, aux0(1) == aux0(0)", Self::NAME),
                cb.next.state.aux0.expr(),
                cb.curr.state.aux0.expr(),
            );
            cb.require_equal(
                format!("{}, aux1(1) == aux1(0)", Self::NAME),
                cb.next.state.aux1.expr(),
                cb.curr.state.aux1.expr(),
            );
        });

        cb.last_row(|cb| {
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Delta(1.expr())),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        BorrowLoc {
            phantom_data: PhantomData,
        }
    }
}
