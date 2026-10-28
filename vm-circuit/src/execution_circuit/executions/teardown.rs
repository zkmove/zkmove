// Copyright (c) zkMove Authors

use crate::execution_circuit::executions::BaseConstraintGadget;
use crate::execution_circuit::step::StepState;
use crate::execution_circuit::InstructionGadgetV2;
use crate::utils::vm_constraint_builder::VmConstraintBuilder;
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use field_exts::util::Expr;
use field_exts::util::{pow_of_two, pow_of_two_expr};
use field_exts::Field;
use gadgets::lt::LtGadget;
use gadgets::range_check::RangeCheckGadget;
use halo2_proofs::plonk::{ErrorFront as Error, Expression};
use halo2_proofs::poly::Rotation;
use value_type::sub_index::NUM_OF_BYTES_SUB_INDEX;
use witness::static_info::StaticInfo;
use witness::step_state::ExecutionState;
use witness::step_state::StageState;

use crate::public_inputs::InstanceTable;

/// Number of bytes of the packed local address
/// `frame_index(10 bits) | local_index(8 bits) | sub_index(64 bits)`.
///
/// The address is 82 bits wide, so 11 bytes are enough to compare it.
const NUM_OF_BYTES_ADDRESS_KEY: usize = 11;

#[derive(Clone, Debug)]
pub struct Teardown<F> {
    lt_gadget: LtGadget<F, NUM_OF_BYTES_ADDRESS_KEY>,
    sub_index_range_check: RangeCheckGadget<F, NUM_OF_BYTES_SUB_INDEX>,
}

/// Returns the packed address key `frame * 2^72 + index * 2^64 + sub_index`
/// of the step state at `offset`.
///
/// The key is injective: `local_frame_index` is range checked to 10 bits and
/// `local_index` to 8 bits by their lookup cells, while `local_sub_index` is
/// range checked to 64 bits by the teardown gadget.
fn key_expr_at<F: Field>(
    cb: &mut VmConstraintBuilder<F>,
    state: &StepState<F>,
    offset: i32,
) -> Expression<F> {
    let frame_lo = cb
        .cell_at_offset(&state.local_frame_index.lo(), offset)
        .expr();
    let frame_hi = cb
        .cell_at_offset(&state.local_frame_index.hi(), offset)
        .expr();
    let frame = frame_lo + frame_hi * pow_of_two_expr(8);
    let index = cb.cell_at_offset(&state.local_index, offset).expr();
    let sub_index = cb.cell_at_offset(&state.local_sub_index, offset).expr();
    frame * pow_of_two_expr(72) + index * pow_of_two_expr(64) + sub_index
}

impl<F: Field> InstructionGadgetV2<F> for Teardown<F> {
    const NAME: &'static str = "Teardown";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Teardown;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        cb.require_zero(
            format!("{}, opcode = 0", Self::NAME),
            cb.curr.state.opcode.expr(),
        );
        cb.require_zero(
            format!("{}, local_write_version(0) == 1", Self::NAME),
            1u64.expr() - cb.curr.state.local_write_version.expr(),
        );

        // The address key compares `local_sub_index` as a 64-bit integer, so
        // make sure it is actually bounded by 2^64.
        let sub_index_range_check = RangeCheckGadget::<F, NUM_OF_BYTES_SUB_INDEX>::construct(
            cb,
            cb.curr.state.local_sub_index.expr(),
        );

        cb.require_no_stack_pop();
        cb.require_no_stack_push();

        let state = cb.curr.state.clone();
        let mut lt = None;
        cb.not_first_row(|cb| {
            let prev_key = key_expr_at(cb, &state, -1);
            let cur_key = key_expr_at(cb, &state, 0);
            let lt_gadget =
                LtGadget::<F, NUM_OF_BYTES_ADDRESS_KEY>::construct(cb, prev_key, cur_key);
            cb.require_true(
                format!("{}, prev_address < cur_address", Self::NAME),
                lt_gadget.expr(),
            );
            lt = Some(lt_gadget);
        });

        cb.not_last_row(|cb| {
            cb.require_next_state(ExecutionState::Teardown);
        });
        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::Stop);
        });

        Self {
            lt_gadget: lt.unwrap(),
            sub_index_range_check,
        }
    }
    fn assign_common(
        &self,
        base_constraint_gadget: &BaseConstraintGadget<F>,
        step_state: &StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        assert_eq!(stage_state.step_states.len(), 1);
        let state = stage_state.step_states.first().unwrap();

        // assign step state because they are same, and need to be assigned at stage0.
        let mut step_counter = state.memory_ops.len();
        for i in 0..state.memory_ops.len() {
            step_state.assign_step_state(region, offset + i, step_counter, &state.step_state)?;
            step_counter -= 1;
        }

        // Sort by address so that the circuit can enforce strictly increasing
        // addresses, i.e. exactly one teardown row per local address.
        let mut memory_ops = state.memory_ops.clone();
        memory_ops.sort_by_key(|op| {
            let local_rw = op.2.as_ref().unwrap();
            let sub_index: u64 = local_rw.sub_index.clone().into();
            (local_rw.frame_index, local_rw.index, sub_index)
        });

        // then assign the memory and base
        for (i, op) in memory_ops.iter().enumerate() {
            step_state.assign_memory_op(region, offset + i, op)?;
            base_constraint_gadget.assign(step_state.clone(), region, offset + i)?;
        }
        Ok(stage_state.rows())
    }
    fn assign(
        &self,
        step_state: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        debug_assert!(stage_state.rows() > 0);

        let rows = stage_state.rows();
        let mut keys = Vec::with_capacity(rows);
        let mut sub_indices = Vec::with_capacity(rows);
        for i in 0..rows {
            let frame_lo = region.get_advice(
                offset + i,
                step_state.local_frame_index.lo().get_column_idx(),
                Rotation::cur(),
            );
            let frame_hi = region.get_advice(
                offset + i,
                step_state.local_frame_index.hi().get_column_idx(),
                Rotation::cur(),
            );
            let frame = frame_hi * pow_of_two::<F>(8) + frame_lo;
            let index = region.get_advice(
                offset + i,
                step_state.local_index.get_column_idx(),
                Rotation::cur(),
            );
            let sub_index = region.get_advice(
                offset + i,
                step_state.local_sub_index.get_column_idx(),
                Rotation::cur(),
            );
            keys.push(frame * pow_of_two::<F>(72) + index * pow_of_two::<F>(64) + sub_index);
            sub_indices.push(sub_index);
        }

        let mut sorted = keys.clone();
        sorted.sort();
        debug_assert_eq!(keys, sorted, "teardown rows must be sorted by address");

        let mut prev_key = F::zero();
        for (i, key) in keys.iter().enumerate() {
            self.sub_index_range_check
                .assign(region, offset + i, sub_indices[i])?;
            let _ = self.lt_gadget.assign(region, offset + i, prev_key, *key)?;
            prev_key = *key;
        }
        Ok(rows)
    }
}
