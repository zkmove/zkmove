use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::step::{StepState, PC, SP};
use crate::execution_circuit::InstructionGadgetV2;
use crate::public_inputs::InstanceTable;
use crate::utils::vm_constraint_builder::{Transition, VmConstraintBuilder};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use field_exts::Field;
use halo2_proofs::plonk::ErrorFront as Error;
use std::marker::PhantomData;
use util::Expr;
use witness::static_info::StaticInfo;
use witness::step_state::StageState;

#[derive(Clone, Debug)]
pub struct LdBool<F, const TRUE: bool> {
    phantom_data: PhantomData<F>,
}
impl<F: Field, const TRUE: bool> InstructionGadgetV2<F> for LdBool<F, TRUE> {
    const NAME: &'static str = match TRUE {
        true => "LdTrue",
        false => "LdFalse",
    };
    const EXECUTION_STATE: ExecutionState = match TRUE {
        true => ExecutionState::LdTrue,
        false => ExecutionState::LdFalse,
    };

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        cb.require_in_set(
            format!("{}, opcode in OPCODES", Self::NAME),
            cb.curr.state.opcode.expr(),
            Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
        );

        cb.require_equal(
            format!("{}, step_counter(0) == 1", Self::NAME),
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

        match TRUE {
            true => {
                cb.require_equal(
                    format!("{}, stack_push_value(0) == true", Self::NAME),
                    cb.curr.state.stack_push_value.expr(),
                    1u64.expr(),
                );
            }
            false => {
                cb.require_zero(
                    format!("{}, stack_push_value(0) == false", Self::NAME),
                    cb.curr.state.stack_push_value.expr(),
                );
            }
        }

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
            (SP, Transition::Delta(1.expr())),
            (PC, Transition::Delta(1.expr())),
        ]);

        LdBool {
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
