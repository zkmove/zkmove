// Copyright (c) zkMove Authors

use crate::chips::execution_chip_v2::instance::InstanceTable;
use crate::chips::execution_chip_v2::step_v2::StepState;
use crate::chips::execution_chip_v2::step_v2::{PC, SP};
use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::Transition;
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::utils::cached_region::CachedRegion;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::ExecutionState;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::Expr;
use halo2_proofs::plonk::ErrorFront as Error;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct Nop<F> {
    phantom_data: PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for Nop<F> {
    const NAME: &'static str = "Nop";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Nop;

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

        cb.require_no_stack_pop();
        cb.require_no_stack_push();
        cb.require_no_local_op();

        cb.require_state_transition(vec![
            (SP, Transition::Same),
            (PC, Transition::Delta(1.expr())),
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
