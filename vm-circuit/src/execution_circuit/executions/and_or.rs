use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::step::{StepState, PC, SP};
use crate::execution_circuit::InstructionGadgetV2;
use crate::public_inputs::InstanceTable;
use crate::utils::vm_constraint_builder::{Transition, VmConstraintBuilder};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use field_exts::Field;
use gadgets::is_zero::IsZeroGadget;
use halo2_proofs::plonk::ErrorFront as Error;
use move_binary_format::file_format_common::Opcodes;
use util::{and, or, Expr};
use witness::static_info::StaticInfo;
use witness::step_state::StageState;

#[derive(Clone, Debug)]
pub struct AndOr<F> {
    is_and: IsZeroGadget<F>,
}
impl<F: Field> InstructionGadgetV2<F> for AndOr<F> {
    const NAME: &'static str = "AndOr";
    const EXECUTION_STATE: ExecutionState = ExecutionState::AndOr;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let is_and =
            IsZeroGadget::construct(cb, step_curr.opcode.expr() - (Opcodes::AND as u64).expr());

        cb.first_row(|cb| {
            cb.require_in_set(
                format!("{}, opcode in OPCODES", Self::NAME),
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.require_equal(
                format!("{}, step_counter(0) == 2", Self::NAME),
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr(),
            );
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

        cb.require_zero(
            format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_boolean(
            format!("{}, stack_pop_value(0) == 0 | 1", Self::NAME),
            step_curr.stack_pop_value.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_value_header(0) == false", Self::NAME),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_no_local_op();

        cb.last_row(|cb| {
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );
            let and = and::expr([
                step_prev.stack_pop_value.expr(),
                step_curr.stack_pop_value.expr(),
            ]);
            let or = or::expr([
                step_prev.stack_pop_value.expr(),
                step_curr.stack_pop_value.expr(),
            ]);
            let expected = is_and.expr() * and + (1u64.expr() - is_and.expr()) * or;
            cb.require_equal(
                format!("{}, stack_push_value(0) == expected", Self::NAME),
                step_curr.stack_push_value.expr(),
                expected,
            );
            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                step_curr.stack_push_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            cb.require_state_transition(vec![
                (SP, Transition::Delta((-1).expr())),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        AndOr { is_and }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        let step_state = stage_state.step_states.first().unwrap();
        debug_assert_eq!(step_state.memory_ops.len(), 2);
        for i in 0..step_state.memory_ops.len() {
            self.is_and.assign(
                region,
                offset + i,
                F::from(step_state.step_state.opcode as u64) - F::from(Opcodes::AND as u64),
            )?;
        }
        Ok(stage_state.rows())
    }
}
