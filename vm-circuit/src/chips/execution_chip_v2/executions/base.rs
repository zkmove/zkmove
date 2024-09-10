use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::math_gadgets::range_check::RangeCheckGadget;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, AUX0, AUX1, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, OPCODE, PC, STEP_COUNTER,
};
use crate::utils::cached_region::CachedRegion;
use aptos_move_witnesses::exec_state::ExecutionState;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::Expr;
use halo2_proofs::plonk::Error;
use halo2_proofs::poly::Rotation;
use types::Field;

#[derive(Clone, Debug)]
pub(crate) struct BaseConstraintGadget<F> {
    stack_pop_version_range_check: RangeCheckGadget<F, 4>,
    local_read_version_range_check: RangeCheckGadget<F, 4>,
}

impl<F: Field> BaseConstraintGadget<F> {
    pub fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        // common constraint for every opcode
        // meta.create_gate("first_row_of_bytecode", |meta| {});
        cb.last_row(|cb| {
            cb.require_equal(
                "step_counter(0)==1",
                cb.curr.state.step_counter.expr(),
                1u64.expr(),
            );
        });
        cb.not_last_row(|cb| {
            // step_counter--
            cb.require_state_transition(vec![(STEP_COUNTER, Transition::Delta((-1).expr()))]);
            cb.require_state_transition(
                [
                    FRAME_INDEX,
                    MODULE_INDEX,
                    FUNCTION_INDEX,
                    OPCODE,
                    PC,
                    AUX0,
                    AUX1,
                ]
                .into_iter()
                .map(|state_name| (state_name, Transition::Same))
                .collect(),
            );
        });

        // stack_pop_version(0) < clk(0)
        let stack_pop_version_range_check = RangeCheckGadget::construct(
            cb,
            cb.curr.state.clk.expr() - cb.curr.state.stack_pop_version.expr(),
        );
        // local_read_version(0) < clk(0)
        let local_read_version_range_check = RangeCheckGadget::construct(
            cb,
            cb.curr.state.clk.expr() - cb.curr.state.local_read_version.expr(),
        );

        Self {
            stack_pop_version_range_check,
            local_read_version_range_check,
        }
    }

    pub fn assign(
        &self,
        step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        _stage_state: &StageState,
        _static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        let clk = region.get_advice(offset, step.clk.get_column_idx(), Rotation::cur());
        let stack_pop_version = region.get_advice(
            offset,
            step.stack_pop_version.get_column_idx(),
            Rotation::cur(),
        );
        let local_read_version = region.get_advice(
            offset,
            step.local_read_version.get_column_idx(),
            Rotation::cur(),
        );
        self.stack_pop_version_range_check
            .assign(region, offset, clk - stack_pop_version)?;
        self.local_read_version_range_check
            .assign(region, offset, clk - local_read_version)?;

        Ok(1)
    }
}
