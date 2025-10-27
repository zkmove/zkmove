// Copyright (c) zkMove Authors

use crate::execution_circuit::step::StepState;
use crate::execution_circuit::InstructionGadgetV2;
use crate::public_inputs::InstanceTable;
use crate::utils::vm_constraint_builder::VmConstraintBuilder;
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use field_exts::util::Expr;
use field_exts::Field;
use halo2_proofs::plonk::ErrorFront as Error;
use std::marker::PhantomData;
use witness::static_info::StaticInfo;
use witness::step_state::ExecutionState;
use witness::step_state::StageState;

#[derive(Clone, Debug)]
pub struct Stop<F> {
    phantom_data: PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for Stop<F> {
    const NAME: &'static str = "Stop";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Stop;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        cb.require_zero(
            format!("{}, opcode = 0", Self::NAME),
            step_curr.opcode.expr(),
        );

        cb.require_equal(
            format!("{}, step_counter(0) == 1", Self::NAME),
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
