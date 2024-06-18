use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::value::Index;
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct BorrowLoc<const MUTABLE: bool, F> {
    phantom_data: PhantomData<F>,
}
impl<const MUTABLE: bool, F: Field> InstructionGadgetV2<F> for BorrowLoc<MUTABLE, F> {
    const NAME: &'static str = "BorrowLoc";

    const OPCODES: &'static [Opcode] = if MUTABLE {
        &[Opcode::MutBorrowLoc]
    } else {
        &[Opcode::ImmBorrowLoc]
    };
    const EXECUTION_STATE: ExecutionState = if MUTABLE {
        ExecutionState::MutBorrowLoc
    } else {
        ExecutionState::ImmBorrowLoc
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        cb.require_in_set(
            "opcode in OPCODES",
            step_curr.opcode.expr(),
            Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
        );
        cb.require_equal(
            format!("{}, step_counter(0) == 1", Self::NAME),
            step_curr.step_counter.expr(),
            1u64.expr(),
        );
        let index = Index::new(step_curr.frame_index.expr(), step_curr.aux0.expr());
        cb.require_equal(
            format!("{}, stack_push_value(0).index == index", Self::NAME),
            step_curr.stack_push_value.as_reference().index(),
            index.expr(),
        );
        cb.require_equal(
            format!("{}, stack_push_value(0).sub_index == sub_index", Self::NAME),
            step_curr.stack_push_value.as_reference().sub_index(),
            0u64.expr(),
        );
        cb.require_zero(
            format!("{}, stack_push_value_header(0) == false", Self::NAME),
            cb.curr.state.stack_push_value_header.expr(),
        );
        cb.require_equal(
            format!("{}, stack_push_index(0) == sp(0) + 1", Self::NAME),
            cb.curr.state.stack_push_index.expr(),
            cb.curr.state.sp.expr() + 1u64.expr(),
        );
        cb.require_zero(
            format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
            cb.curr.state.stack_push_sub_index.expr(),
        );
        cb.require_equal(
            format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
            cb.curr.state.stack_push_version.expr(),
            cb.curr.state.clk.expr(),
        );
        cb.require_no_stack_pop();
        cb.require_no_local_op();
        cb.require_state_transition(vec![
            (FRAME_INDEX, Transition::Same),
            (MODULE_INDEX, Transition::Same),
            (FUNCTION_INDEX, Transition::Same),
            (SP, Transition::Delta(1.expr())),
            (PC, Transition::Delta(1.expr())),
        ]);

        BorrowLoc {
            phantom_data: PhantomData,
        }
    }
}
