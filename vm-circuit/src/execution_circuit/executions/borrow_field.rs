use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::executions::ExtendedSubIndex;
use crate::execution_circuit::step::{StepState, PC, SP};
use crate::execution_circuit::InstructionGadgetV2;
use crate::public_inputs::InstanceTable;
use crate::utils::vm_constraint_builder::{Transition, VmConstraintBuilder};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use field_exts::util::Expr;
use field_exts::Field;
use halo2_proofs::plonk::ErrorFront as Error;
use witness::static_info::StaticInfo;
use witness::step_state::StageState;

#[derive(Clone, Debug)]
pub struct BorrowField<F> {
    stack_pop_value_sub_index: ExtendedSubIndex<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for BorrowField<F> {
    const NAME: &'static str = "BorrowField";
    const EXECUTION_STATE: ExecutionState = ExecutionState::BorrowField;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        cb.require_in_set(
            format!("{}, opcode in OPCODES", Self::NAME),
            step_curr.opcode.expr(),
            Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
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
        cb.require_equal(
            format!(
                "{}, stack_push_value(0).index == stack_pop_value(0).index",
                Self::NAME
            ),
            step_curr.stack_push_value.as_reference().index(),
            step_curr.stack_pop_value.as_reference().index(),
        );
        let stack_pop_value_sub_index =
            ExtendedSubIndex::construct(cb, step_curr.stack_pop_value.as_reference().sub_index());
        cb.require_equal(
            format!("{}, stack_push_value(0).sub_index == stack_pop_value(0).sub_index.concat(operand0(0) + 1)", Self::NAME),
            step_curr.stack_push_value.as_reference().sub_index(),
            stack_pop_value_sub_index.concat(step_curr.operand0.expr() + 1u64.expr()),
        );
        cb.require_equal(
            format!(
                "{}, stack_push_value_header(0) == stack_pop_value_header(0)",
                Self::NAME
            ),
            step_curr.stack_push_value_header.expr(),
            step_curr.stack_pop_value_header.expr(),
        );
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
            format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
            step_curr.stack_push_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_no_local_op();
        cb.require_state_transition(vec![
            (SP, Transition::Same),
            (PC, Transition::Delta(1.expr())),
        ]);

        BorrowField {
            stack_pop_value_sub_index,
        }
    }

    fn assign(
        &self,
        __step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        debug_assert_eq!(stage_state.step_states.len(), 1);
        let step_state = stage_state.step_states.first().unwrap();
        let stack_pop_value_sub_index = step_state.memory_ops[0].0.clone().unwrap().value.hi(); // TODO: use reference
        self.stack_pop_value_sub_index.assign(
            region,
            offset,
            F::from_u128(stack_pop_value_sub_index),
        )?;
        Ok(step_state.memory_ops.len())
    }
}
