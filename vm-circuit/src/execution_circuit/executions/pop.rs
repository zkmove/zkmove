use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::step::{StepState, PC, SP};
use crate::execution_circuit::InstructionGadgetV2;
use crate::public_inputs::InstanceTable;
use crate::utils::vm_constraint_builder::{Transition, VmConstraintBuilder};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use field_exts::util::Expr;
use field_exts::Field;
use halo2_proofs::plonk::ErrorFront as Error;
use std::marker::PhantomData;
use witness::static_info::StaticInfo;
use witness::step_state::StageState;

#[derive(Clone, Debug, Default)]
pub struct Pop<F>(PhantomData<F>);
impl<F: Field> InstructionGadgetV2<F> for Pop<F> {
    const NAME: &'static str = "Pop";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Pop;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_in_set(
                format!("{}, opcode in OPCODES", Self::NAME),
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.condition(step_curr.stack_pop_value_header.expr(), |cb| {
                cb.require_equal(
                    format!("{}, step_counter(0) == flen", Self::NAME),
                    step_curr.step_counter.expr(),
                    step_curr.stack_pop_value.as_header().flen(),
                );
            });
            cb.condition(
                1u64.expr() - step_curr.stack_pop_value_header.expr(),
                |cb| {
                    cb.require_equal(
                        format!("{}, step_counter(0) == 1", Self::NAME),
                        step_curr.step_counter.expr(),
                        1u64.expr(),
                    );
                },
            );
        });
        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.first_row(|cb| {
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                step_curr.stack_pop_sub_index.expr(),
            );
        });
        cb.require_no_stack_push();
        cb.require_no_local_op();

        // nexts
        cb.last_row(|cb| {
            cb.require_state_transition(vec![
                (PC, Transition::Delta(1.expr())),
                (SP, Transition::Delta((-1).expr())),
            ]);
        });
        Self::default()
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
