// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::step_v2::StepState;
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::utils::cached_region::CachedRegion;
use aptos_move_witnesses::exec_state::ExecutionState;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::Expr;
use halo2_proofs::plonk::Error;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct Nop<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for Nop<F> {
    const NAME: &'static str = "Mul_Div_Mod";
    const OPCODE: Opcode = Opcode::Mul; //TODO: remove this
    const EXECUTION_STATE: ExecutionState = ExecutionState::MulDivMod;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.require_equal(
            "opcode = NOP",
            cb.curr.state.opcode.expr(),
            (Self::OPCODE as u64).expr(),
        );
        cb.require_zero(
            "local_write_version(0) ==0",
            cb.curr.state.local_write_version.expr(),
        );

        Self {
            _marker: PhantomData,
        }
    }
    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
    ) -> Result<usize, Error> {
        Ok(stage_state.rows())
    }
}
