use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::executions::ExtendedSubIndex;
use crate::execution_circuit::step::{StepState, PC, SP};
use crate::execution_circuit::value::Index;
use crate::execution_circuit::InstructionGadgetV2;
use crate::public_inputs::InstanceTable;
use crate::utils::vm_constraint_builder::{Transition, VmConstraintBuilder};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use circuit_tool::cell_manager::Cell;
use field_exts::util::Expr;
use field_exts::Field;
use halo2_proofs::{circuit::Value, plonk::ErrorFront as Error};
use value_type::utils::ToField;
use witness::static_info::StaticInfo;
use witness::step_state::StageState;

#[derive(Clone, Debug)]
pub struct ReadRef<F> {
    header_sub_index: Cell<F>,
    header_sub_index_ext: ExtendedSubIndex<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for ReadRef<F> {
    const NAME: &'static str = "ReadRef";
    const EXECUTION_STATE: ExecutionState = ExecutionState::ReadRef;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        let header_sub_index = cb.query_cell();
        let header_sub_index_ext = ExtendedSubIndex::construct(cb, header_sub_index.expr());
        let step_curr = cb.curr.state.clone();
        let step_next = cb.step_state_at_offset(1);

        cb.first_row(|cb| {
            cb.require_in_set(
                format!("{}, opcode in OPCODES", Self::NAME),
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr(),
            );
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                step_curr.stack_pop_sub_index.expr(),
            );
            let index = Index::new(step_curr.local_frame_index.expr(), step_curr.local_index.expr());
            cb.require_equal(
                format!("{}, (local_frame_index(0), local_index(0)) == stack_pop_value(0).index", Self::NAME),
                index.expr(),
                step_curr.stack_pop_value.as_reference().index(),
            );
            cb.require_equal(
                format!("{}, local_sub_index(0) == stack_pop_value(0).sub_index", Self::NAME),
                step_curr.local_sub_index.expr(),
                step_curr.stack_pop_value.as_reference().sub_index(),
            );

            //if !local_read_value_header(0) { step_counter(0) == 1; }
            cb.require_zero(
                format!(
                    "{}, (1 - local_read_value_header(0)) * (step_counter(0) - 1) == 0",
                    Self::NAME
                ),
                (1u64.expr() - step_curr.local_read_value_header.expr())
                    * (step_curr.step_counter.expr() - 1u64.expr()),
            );
            //if local_read_value_header(0) { step_counter(0) == local_read_value(0).f_len; }
            cb.require_zero(
                format!(
                    "{}, local_read_value_header(0) * (step_counter(0) - local_read_value(0).flen) == 0",
                    Self::NAME
                ),
                step_curr.local_read_value_header.expr()
                    * (step_curr.step_counter.expr() - step_curr.local_read_value.as_header().flen()),
            );
            // record the sub index of the referenced value's header
            cb.require_equal(
                format!("{}, header_sub_index(0) == local_sub_index(0)", Self::NAME),
                header_sub_index.expr(),
                step_curr.local_sub_index.expr(),
            );
        });
        cb.not_first_row(|cb| {
            cb.require_no_stack_pop();
        });

        cb.require_equal(
            format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
            step_curr.stack_push_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_equal(
            format!("{}, local_sub_index(0) == concat(header_sub_index(0), nonzero(stack_push_sub_index(0)))" , Self::NAME),
            step_curr.local_sub_index.expr(),
            header_sub_index_ext.concat(step_curr.stack_push_sub_index.expr()),
        );
        cb.require_equal(
            format!("{}, stack_push_value(0) == local_read_value(0)", Self::NAME),
            step_curr.stack_push_value.expr(),
            step_curr.local_read_value.expr(),
        );
        cb.require_equal(
            format!(
                "{}, stack_push_value_header(0) == local_read_value_header(0)",
                Self::NAME
            ),
            step_curr.stack_push_value_header.expr(),
            step_curr.local_read_value_header.expr(),
        );
        cb.require_equal(
            format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
            step_curr.stack_push_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value(0) == local_read_value(0)",
                Self::NAME
            ),
            step_curr.local_write_value.expr(),
            step_curr.local_read_value.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value_invalid(0) == local_read_value_invalid(0)",
                Self::NAME
            ),
            step_curr.local_write_value_invalid.expr(),
            step_curr.local_read_value_invalid.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value_header(0) == local_read_value_header(0)",
                Self::NAME
            ),
            step_curr.local_write_value_header.expr(),
            step_curr.local_read_value_header.expr(),
        );
        cb.require_equal(
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );

        cb.require_state_transition(vec![(SP, Transition::Same)]);
        cb.not_last_row(|cb| {
            cb.require_equal(
                format!(
                    "{}, local_frame_index(1) == local_frame_index(0)",
                    Self::NAME
                ),
                step_next.local_frame_index.expr(),
                step_curr.local_frame_index.expr(),
            );
            cb.require_equal(
                format!("{}, local_index(1) == local_index(0)", Self::NAME),
                step_next.local_index.expr(),
                step_curr.local_index.expr(),
            );
            let header_sub_index_next = cb.cell_at_offset(&header_sub_index, 1).expr();
            cb.require_equal(
                format!("{}, header_sub_index(1) == header_sub_index(0)", Self::NAME),
                header_sub_index_next,
                header_sub_index.expr(),
            );
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![(PC, Transition::Delta(1.expr()))]);
        });

        ReadRef {
            header_sub_index,
            header_sub_index_ext,
        }
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
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();
        debug_assert!(!step_state.memory_ops.is_empty());
        let header_sub_index = &step_state
            .memory_ops
            .first()
            .unwrap()
            .2
            .as_ref()
            .unwrap()
            .sub_index;
        let rows = step_state.memory_ops.len();
        (0..rows)
            .map(|i| {
                self.header_sub_index.assign(
                    region,
                    offset + i,
                    Value::known(header_sub_index.to_field()),
                )?;
                self.header_sub_index_ext
                    .assign(region, offset + i, header_sub_index.to_field())
            })
            .try_fold((), |_, res| res)?;
        Ok(rows)
    }
}
