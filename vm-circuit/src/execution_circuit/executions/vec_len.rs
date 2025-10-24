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
pub struct VecLen<F> {
    phantom_data: PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for VecLen<F> {
    const NAME: &'static str = "VecLen";
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecLen;

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
        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
            step_curr.stack_pop_sub_index.expr(),
        );

        let index = Index::new(
            step_curr.local_frame_index.expr(),
            step_curr.local_index.expr(),
        );
        cb.require_equal(
            format!(
                "{}, (local_frame_index(0), local_index(0)) == stack_pop_value(0).index",
                Self::NAME
            ),
            index.expr(),
            step_curr.stack_pop_value.as_reference().index(),
        );
        cb.require_equal(
            format!(
                "{}, local_sub_index(0) == stack_pop_value(0).sub_index",
                Self::NAME
            ),
            step_curr.local_sub_index.expr(),
            step_curr.stack_pop_value.as_reference().sub_index(),
        );
        cb.require_true(
            format!("{}, local_read_value_header(0) == true", Self::NAME),
            step_curr.local_read_value_header.expr(),
        );
        cb.require_zero(
            format!("{}, local_read_value_invalid(0) == false", Self::NAME),
            step_curr.local_read_value_invalid.expr(),
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
        cb.require_equal(
            format!(
                "{}, local_write_value_invalid(0) == local_read_value_invalid(0)",
                Self::NAME
            ),
            step_curr.local_write_value_invalid.expr(),
            step_curr.local_read_value_invalid.expr(),
        );
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
            format!(
                "{}, stack_push_value(0).as_integer().lo == local_read_value(0).as_header().len",
                Self::NAME
            ),
            step_curr.stack_push_value.as_integer().lo(),
            step_curr.local_read_value.as_header().len(),
        );
        cb.require_zero(
            format!("{}, stack_push_value(0).as_integer().hi == 0", Self::NAME),
            step_curr.stack_push_value.as_integer().hi(),
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
            (PC, Transition::Delta(1.expr())),
            (SP, Transition::Same),
        ]);

        VecLen {
            phantom_data: PhantomData,
        }
    }
}
