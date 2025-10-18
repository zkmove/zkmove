// Copyright (c) zkMove Authors

use crate::execution_circuit::instance::InstanceTable;
use crate::execution_circuit::step::StepState;
use crate::execution_circuit::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::execution_circuit::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::execution_circuit::InstructionGadgetV2;
use crate::utils::cached_region::CachedRegion;
use gadgets::util::Expr;
use halo2_proofs::plonk::ErrorFront as Error;
use std::marker::PhantomData;
use types::Field;
use witnesses::static_info::StaticInfo;
use witnesses::step_state::ExecutionState;
use witnesses::step_state::StageState;

#[derive(Clone, Debug)]
pub struct ErrorState<F> {
    phantom_data: PhantomData<F>,
}

// TODO: we only have a skeleton, still need to fill in the details, such as handling ErrorCode

impl<F: Field> InstructionGadgetV2<F> for ErrorState<F> {
    const NAME: &'static str = "ErrorState";
    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorState;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        cb.require_zero("opcode = 0", step_curr.opcode.expr());

        cb.require_equal(
            "step_counter(0) == 1",
            step_curr.step_counter.expr(),
            1u64.expr(),
        );

        cb.require_no_stack_pop();
        cb.require_no_stack_push();
        cb.require_no_local_op();

        cb.require_next_states(vec![ExecutionState::Teardown, ExecutionState::Stop]);

        Self {
            phantom_data: PhantomData,
        }
    }

    fn assign(
        &self,
        _step_state: StepState<F>,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        debug_assert!(stage_state.rows() == 1);
        Ok(stage_state.rows())
    }
}
