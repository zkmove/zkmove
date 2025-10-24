use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::step::{PC, SP};
use crate::execution_circuit::value::Index;
use crate::execution_circuit::InstructionGadgetV2;
use crate::utils::vm_constraint_builder::{Transition, VmConstraintBuilder};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use field_exts::Field;
use std::marker::PhantomData;
use util::Expr;

#[derive(Clone, Debug)]
pub struct BorrowLoc<F> {
    phantom_data: PhantomData<F>,
}
impl<F: Field> InstructionGadgetV2<F> for BorrowLoc<F> {
    const NAME: &'static str = "BorrowLoc";
    const EXECUTION_STATE: ExecutionState = ExecutionState::BorrowLoc;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        cb.require_in_set(
            format!("{}, opcode in OPCODES", Self::NAME),
            step_curr.opcode.expr(),
            Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
        );
        cb.require_equal(
            format!("{}, step_counter(0) == 1", Self::NAME),
            step_curr.step_counter.expr(),
            1u64.expr(),
        );
        let index = Index::new(step_curr.frame_index.expr(), step_curr.operand0.expr());
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
            step_curr.stack_push_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_no_stack_pop();
        cb.require_no_local_op();
        cb.require_state_transition(vec![
            (SP, Transition::Delta(1.expr())),
            (PC, Transition::Delta(1.expr())),
        ]);

        BorrowLoc {
            phantom_data: PhantomData,
        }
    }
}
