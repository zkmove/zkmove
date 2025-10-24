use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::step::{PC, SP};
use crate::execution_circuit::InstructionGadgetV2;
use crate::utils::vm_constraint_builder::{Transition, VmConstraintBuilder};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use field_exts::Field;
use std::marker::PhantomData;
use util::Expr;

#[derive(Clone, Debug)]
pub struct Branch<F> {
    phantom_data: PhantomData<F>,
}
impl<F: Field> InstructionGadgetV2<F> for Branch<F> {
    const NAME: &'static str = "BRANCH";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Branch;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        cb.first_row(|cb| {
            cb.require_in_set(
                format!("{}, opcode in OPCODES", Self::NAME),
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

        let next_pc = cb.curr.state.operand0.expr();

        cb.require_state_transition(vec![(SP, Transition::Same), (PC, Transition::To(next_pc))]);

        Branch {
            phantom_data: PhantomData,
        }
    }
}
