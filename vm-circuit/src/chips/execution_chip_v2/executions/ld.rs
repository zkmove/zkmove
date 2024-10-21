use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::step_v2::{StepState, PC, SP};
use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::{
    ConstraintBuilderV2, Transition,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::utils::cached_region::CachedRegion;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::Expr;
use halo2_proofs::plonk::Error;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct LdSimple<F> {
    phantom_data: PhantomData<F>,
}
impl<F: Field> InstructionGadgetV2<F> for LdSimple<F> {
    const NAME: &'static str = "LoadSimple";
    const EXECUTION_STATE: ExecutionState = ExecutionState::LdSimple;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.require_in_set(
            "opcode in OPCODES",
            cb.curr.state.opcode.expr(),
            Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
        );

        cb.require_equal(
            "step_counter(0) == 1",
            cb.curr.state.step_counter.expr(),
            1u64.expr(),
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
            format!("{}, stack_push_value(0).lo == aux0(0)", Self::NAME),
            cb.curr.state.stack_push_value.as_integer().lo(),
            cb.curr.state.aux0.expr(),
        );
        cb.require_equal(
            format!("{}, stack_push_value(0).hi == aux1(0)", Self::NAME),
            cb.curr.state.stack_push_value.as_integer().hi(),
            cb.curr.state.aux1.expr(),
        );

        cb.require_zero(
            format!("{}, stack_push_value_header(0) == false", Self::NAME),
            cb.curr.state.stack_push_value_header.expr(),
        );
        cb.require_equal(
            "stack_push_version(0) == clk(0)",
            cb.curr.state.stack_push_version.expr(),
            cb.curr.state.clk.expr(),
        );

        cb.require_no_stack_pop();
        cb.require_no_local_op();

        cb.require_state_transition(vec![
            (SP, Transition::Delta(1.expr())),
            (PC, Transition::Delta(1.expr())),
        ]);

        LdSimple {
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
    ) -> Result<usize, Error> {
        // no need to assign anything else
        Ok(stage_state.rows())
    }
}
