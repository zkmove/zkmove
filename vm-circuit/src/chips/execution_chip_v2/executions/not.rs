use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::instance::InstanceTable;
use crate::chips::execution_chip_v2::step_v2::{StepState, PC, SP};
use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::{
    ConstraintBuilderV2, Transition,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::utils::cached_region::CachedRegion;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::not;
use gadgets::util::Expr;
use halo2_proofs::plonk::Error;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct Not<F> {
    phantom_data: PhantomData<F>,
}
impl<F: Field> InstructionGadgetV2<F> for Not<F> {
    const NAME: &'static str = "Not";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Not;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();

        cb.require_in_set(
            "opcode in OPCODES",
            step_curr.opcode.expr(),
            Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
        );
        cb.require_equal(
            "step_counter(0) == 1",
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
        cb.require_boolean(
            "stack_pop_value(0) == 0 | 1",
            step_curr.stack_pop_value.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_value_header(0) == false", Self::NAME),
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
            format!("{}, stack_push_value(0) == !stack_pop_value(0)", Self::NAME),
            step_curr.stack_push_value.expr(),
            not::expr(step_curr.stack_pop_value.expr()),
        );
        cb.require_zero(
            format!("{}, stack_push_value_header(0) == false", Self::NAME),
            step_curr.stack_push_value_header.expr(),
        );
        cb.require_equal(
            "stack_push_version(0) == clk(0)",
            step_curr.stack_push_version.expr(),
            step_curr.clk.expr(),
        );

        cb.require_no_local_op();

        cb.require_state_transition(vec![
            (SP, Transition::Same),
            (PC, Transition::Delta(1.expr())),
        ]);

        Not {
            phantom_data: PhantomData,
        }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        // no need to assign anything else
        Ok(stage_state.rows())
    }
}
