use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::range_check::RangeCheckGadget;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP,
};
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use halo2_proofs::plonk::Error;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct LdSimple<F> {
    phantom_data: PhantomData<F>,
}
impl<F: Field> InstructionGadgetV2<F> for LdSimple<F> {
    const NAME: &'static str = "LoadSimple";
    const OPCODE: Opcode = Opcode::LdU8; //TODO: remove this.
    const EXECUTION_STATE: ExecutionState = ExecutionState::LdSimple;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        // TODO: remove the constraint, also for other opcode
        // Actually we only need lookup (.., pc, opcode,..) in bytecode table.
        // Because pc is constrained by previous step, opcode must be a fixed one.
        // cb.require_equal(
        //     "opcode",
        //     cb.curr.state.opcode.expr(),
        //     (Self::OPCODE as u64).expr(),
        // );

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
            format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
            cb.curr.state.stack_push_version.expr(),
            cb.curr.state.clk.expr(),
        );

        cb.require_no_stack_pop();
        cb.require_no_local_op();

        cb.require_state_transition(vec![
            (FRAME_INDEX, Transition::Same),
            (MODULE_INDEX, Transition::Same),
            (FUNCTION_INDEX, Transition::Same),
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
