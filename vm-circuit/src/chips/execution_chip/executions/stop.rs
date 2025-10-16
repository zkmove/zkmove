// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instance::InstanceTable;
use crate::chips::execution_chip::step::StepState;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip::InstructionGadgetV2;
use crate::utils::cached_region::CachedRegion;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::ExecutionState;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::Expr;
use halo2_proofs::plonk::ErrorFront as Error;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct Stop<F> {
    phantom_data: PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for Stop<F> {
    const NAME: &'static str = "Stop";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Stop;

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

        cb.require_prev_states(vec![
            ExecutionState::Teardown,
            ExecutionState::Ret,
            ExecutionState::Abort,
            // NOTICE: Do not uncomment until correctly implemented.
            //ExecutionState::Error,
            ExecutionState::Stop, //when 'Stop' is used as padding, it can be followed by 'Stop'
        ]);

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
