use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP,
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
pub struct BrBool<F, const TRUE: bool> {
    phantom_data: PhantomData<F>,
}
impl<F: Field, const TRUE: bool> InstructionGadgetV2<F> for BrBool<F, TRUE> {
    const NAME: &'static str = match TRUE {
        true => "BRTRUE",
        false => "BRFALSE",
    };

    const OPCODES: &'static [Opcode] = match TRUE {
        true => &[Opcode::BrTrue],
        false => &[Opcode::BrFalse],
    };
    const EXECUTION_STATE: ExecutionState = match TRUE {
        true => ExecutionState::BrTrue,
        false => ExecutionState::BrFalse,
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in OPCODES",
                cb.curr.state.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.require_zero(
                format!("{}, step_counter(0) == 1", Self::NAME),
                cb.curr.state.step_counter.expr() - 1u64.expr(),
            );
        });

        cb.require_equal(
            "stack_pop_index(0) == sp(0)",
            cb.curr.state.stack_pop_index.expr(),
            cb.curr.state.sp.expr(),
        );
        cb.require_zero(
            "stack_pop_sub_index(0) == 0",
            cb.curr.state.stack_pop_sub_index.expr(),
        );
        let next_pc = cb.curr.state.aux0.expr();
        let branch_condition = cb.curr.state.stack_pop_value.expr();
        // FIXME:  should enfore it in stack_push operation
        // here for demonstration
        cb.require_boolean("boolean branch value", branch_condition.clone());
        let next_step_pc = if TRUE {
            branch_condition.clone() * next_pc
                + (1u64.expr() - branch_condition.clone()) * (cb.curr.state.pc.expr() + 1u64.expr())
        } else {
            (1u64.expr() - branch_condition.clone()) * next_pc
                + branch_condition.clone() * (cb.curr.state.pc.expr() + 1u64.expr())
        };
        cb.require_state_transition(vec![
            (FRAME_INDEX, Transition::Same),
            (MODULE_INDEX, Transition::Same),
            (FUNCTION_INDEX, Transition::Same),
            (SP, Transition::Delta((-1).expr())),
            (PC, Transition::To(next_step_pc)),
        ]);

        BrBool {
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
