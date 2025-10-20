use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::step::{StepState, PC, SP};
use crate::execution_circuit::InstructionGadgetV2;
use crate::public_inputs::InstanceTable;
use crate::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::utils::cached_region::CachedRegion;
use crate::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use gadgets::util::Expr;
use halo2_proofs::plonk::ErrorFront as Error;
use std::marker::PhantomData;
use types::Field;
use witnesses::static_info::StaticInfo;
use witnesses::step_state::StageState;

#[derive(Clone, Debug)]
pub struct BrBool<F, const TRUE: bool> {
    phantom_data: PhantomData<F>,
}
impl<F: Field, const TRUE: bool> InstructionGadgetV2<F> for BrBool<F, TRUE> {
    const NAME: &'static str = match TRUE {
        true => "BRTRUE",
        false => "BRFALSE",
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

        cb.require_no_local_op();
        cb.require_no_stack_push();

        cb.require_equal(
            "stack_pop_index(0) == sp(0)",
            cb.curr.state.stack_pop_index.expr(),
            cb.curr.state.sp.expr(),
        );
        cb.require_zero(
            "stack_pop_sub_index(0) == 0",
            cb.curr.state.stack_pop_sub_index.expr(),
        );
        let next_pc = cb.curr.state.operand0.expr();
        let branch_condition = cb.curr.state.stack_pop_value.expr();
        // FIXME:  should enforce it in stack_push operation
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
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        // no need to assign anything else
        Ok(stage_state.rows())
    }
}
