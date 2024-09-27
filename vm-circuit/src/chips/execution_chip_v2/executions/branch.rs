use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::step_v2::{PC, SP};
use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::{
    ConstraintBuilderV2, Transition,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utils::Expr;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct Branch<F> {
    phantom_data: PhantomData<F>,
}
impl<F: Field> InstructionGadgetV2<F> for Branch<F> {
    const NAME: &'static str = "BRANCH";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Branch;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in OPCODES",
                cb.curr.state.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.require_zero(
                format!("{}, step_counter(0) == 1", Self::NAME),
                cb.curr.state.step_counter.expr() - 1u64.expr(),
            );
        });

        cb.require_no_local_op();
        cb.require_no_stack_pop();
        cb.require_no_stack_push();

        let next_pc = cb.curr.state.aux0.expr();

        cb.require_state_transition(vec![(SP, Transition::Same), (PC, Transition::To(next_pc))]);

        Branch {
            phantom_data: PhantomData,
        }
    }
}
