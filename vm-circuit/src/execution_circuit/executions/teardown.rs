// Copyright (c) zkMove Authors

use crate::execution_circuit::executions::BaseConstraintGadget;
use crate::execution_circuit::step::StepState;
use crate::execution_circuit::InstructionGadgetV2;
use crate::utils::vm_constraint_builder::VmConstraintBuilder;
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use circuit_tool::rlc;
use circuit_tool::word::WordLoHiCell;
use gadgets::lt::LtInteger;
use util::pow_of_two_expr;
use witness::static_info::StaticInfo;
use witness::step_state::ExecutionState;
use witness::step_state::StageState;
use witness::value::utils::ToField;

use crate::public_inputs::InstanceTable;
use field_exts::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::ErrorFront as Error;
use halo2_proofs::poly::Rotation;
use move_core_types::u256::U256;
use util::Expr;

#[derive(Clone, Debug)]
pub struct Teardown<F> {
    rlc: WordLoHiCell<F>,
    lt_gadget: LtInteger<F>,
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
        let cells = cb.query_cells::<2>();
        let rlc = WordLoHiCell::new(cells);
        let cur_rlc = cb.rlc_with_randomness(
            &[
                cb.curr.state.local_frame_index.expr(),
                cb.curr.state.local_index.expr(),
                cb.curr.state.local_sub_index.expr(),
            ],
            cb.row_randomness(),
        );
        cb.require_no_stack_pop();
        cb.require_no_stack_push();
        cb.require_equal(
            format!(
                "{}, rlc(local_frame_index, local_index, local_sub_index) == rlc",
                Self::NAME
            ),
            cur_rlc,
            rlc.hi().expr() * pow_of_two_expr(128) + rlc.lo().expr(),
        );
        let mut lt = None;
        cb.not_first_row(|cb| {
            let prev_lo = cb.cell_at_offset(&rlc.lo(), -1).expr();
            let prev_hi = cb.cell_at_offset(&rlc.hi(), -1).expr();
            let lt_gadget =
                LtInteger::construct(cb, prev_lo, prev_hi, rlc.lo().expr(), rlc.hi().expr());
            cb.require_true(
                format!("{}, prev_rlc < cur_rlc", Self::NAME),
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
            rlc,
            lt_gadget: lt.unwrap(),
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

        let randomness = region.challenges().row_keccak_input();
        // sort by rlc
        let exec_step_state = randomness.map(|randomness| {
            let mut memory_ops = state.memory_ops.clone();
            memory_ops.sort_by_key(|op| {
                let local_rw = op.2.as_ref().unwrap();
                let local_frame_index = F::from(local_rw.frame_index as u64);
                let local_index = F::from(local_rw.index as u64);
                let local_sub_index = local_rw.sub_index.to_field();
                rlc::generic(
                    [local_frame_index, local_index, local_sub_index],
                    randomness,
                )
            });
            memory_ops
        });

        // then assign the memory and base
        exec_step_state
            .map(|s| {
                for (i, op) in s.into_iter().enumerate() {
                    step_state.assign_memory_op(region, offset + i, &op)?;
                    base_constraint_gadget.assign(step_state.clone(), region, offset + i)?;
                }
                Ok::<_, Error>(())
            })
            .error_if_known_and(|r| r.is_err())?;
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

        let randomness = region.challenges().row_keccak_input();

        let unsorted_rlcs: Value<Vec<_>> = Value::from_iter((0..stage_state.rows()).map(|i| {
            let local_frame_index = region.get_advice(
                offset + i,
                step_state.local_frame_index.get_column_idx(),
                Rotation::cur(),
            );
            let local_index = region.get_advice(
                offset + i,
                step_state.local_index.get_column_idx(),
                Rotation::cur(),
            );
            let local_sub_index = region.get_advice(
                offset + i,
                step_state.local_sub_index.get_column_idx(),
                Rotation::cur(),
            );
            randomness.map(|r| rlc::generic([local_frame_index, local_index, local_sub_index], r))
        }));
        let sort_rlcs = unsorted_rlcs.map(|mut l| {
            let before = l.clone();
            l.sort();
            debug_assert_eq!(before, l);
            l
        });
        sort_rlcs.error_if_known_and(|rlcs| {
            let rlcs = rlcs
                .iter()
                .map(|v| {
                    let bytes = v.to_repr();
                    let array: &[u8; 32] = bytes
                        .as_ref()
                        .try_into()
                        .expect("slice with incorrect length");
                    U256::from_le_bytes(array)
                })
                .collect::<Vec<_>>();
            let mut assign_result = vec![];
            let mut prev_rlc = U256::zero();
            for (i, rlc) in rlcs.iter().enumerate().take(stage_state.rows()) {
                assign_result.push(self.rlc.assign_u256(region, offset + i, *rlc).map(|_| ()));
                assign_result.push(self.lt_gadget.assign(region, offset + i, prev_rlc, *rlc));
                prev_rlc = *rlc;
            }
            let assign_result = assign_result.into_iter().collect::<Result<Vec<_>, Error>>();
            assign_result.is_err()
        })?;
        Ok(stage_state.rows())
    }
}
