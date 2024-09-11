// Copyright (c) zkMove Authors

use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::executions::BaseConstraintGadget;
use crate::chips::execution_chip_v2::math_gadgets::lt::LtInteger;
use crate::chips::execution_chip_v2::step_v2::StepState;
use crate::chips::execution_chip_v2::utils::pow_of_two_expr;
use crate::chips::execution_chip_v2::utils::to_field::ToField;
use crate::chips::execution_chip_v2::{assign_step_and_common, InstructionGadgetV2};
use crate::utils::cached_region::CachedRegion;
use crate::utils::rlc;
use crate::utils::word::WordLoHiCell;
use aptos_move_witnesses::exec_state::ExecutionState;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;

use gadgets::util::Expr;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2_proofs::poly::Rotation;
use move_core_types::u256::U256;
use types::Field;

#[derive(Clone, Debug)]
pub struct Nop<F> {
    rlc: WordLoHiCell<F>,
    lt_gadget: LtInteger<F>,
}

impl<F: Field> InstructionGadgetV2<F> for Nop<F> {
    const NAME: &'static str = "Nop";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Nop;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.require_zero("opcode = 0", cb.curr.state.opcode.expr());
        cb.require_zero(
            "local_write_version(0) == 1",
            1u64.expr() - cb.curr.state.local_write_version.expr(),
        );
        let cells = cb.query_cells::<2>();
        let rlc = WordLoHiCell::new(cells);
        let cur_rlc = cb.rlc(&[
            cb.curr.state.local_frame_index.expr(),
            cb.curr.state.local_index.expr(),
            cb.curr.state.local_sub_index.expr(),
        ]);
        cb.require_no_stack_pop();
        cb.require_equal(
            "rlc(local_frame_index, local_index, local_sub_index) == rlc",
            cur_rlc,
            rlc.hi().expr() * pow_of_two_expr(128) + rlc.lo().expr(),
        );
        let mut lt = None;
        cb.not_first_row(|cb| {
            let prev_lo = cb.cell_at_offset(&rlc.lo(), -1).expr();
            let prev_hi = cb.cell_at_offset(&rlc.hi(), -1).expr();
            let lt_gadget =
                LtInteger::construct(cb, prev_lo, prev_hi, rlc.lo().expr(), rlc.hi().expr());
            cb.require_true("prev_rlc < cur_rlc", lt_gadget.expr());
            lt = Some(lt_gadget);
        });

        Self {
            rlc,
            lt_gadget: lt.unwrap(),
        }
    }
    fn assign_common(
        &self,
        base_constraint_gadget: &BaseConstraintGadget<F>,
        step_state: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        assert_eq!(stage_state.step_states.len(), 1);

        let randomness = region.challenges().keccak_input();
        // sort by rlc
        let exec_step_state = randomness.map(|randomness| {
            let mut exec_step_state = stage_state.step_states.first().unwrap().clone();
            exec_step_state.memory_ops.sort_by_key(|op| {
                let local_rw = op.2.as_ref().unwrap();
                let local_frame_index = F::from(local_rw.frame_index as u64);
                let local_index = F::from(local_rw.index as u64);
                let local_sub_index = local_rw.sub_index.to_field();
                rlc::generic(
                    [local_frame_index, local_index, local_sub_index],
                    randomness,
                )
            });
            exec_step_state
        });

        // then assign the step
        exec_step_state
            .map(|s| StageState {
                step_states: vec![s],
                extra_data: stage_state.extra_data.clone(),
            })
            .map(|s| {
                assign_step_and_common(
                    base_constraint_gadget,
                    step_state,
                    region,
                    offset,
                    &s,
                    static_info,
                )
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
    ) -> Result<usize, Error> {
        debug_assert!(stage_state.rows() > 0);

        let randomness = region.challenges().keccak_input();

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
                .map(|v| U256::from_le_bytes(&v.to_repr()))
                .collect::<Vec<_>>();
            let mut assign_result = vec![];
            let mut prev_rlc = U256::zero();
            for i in 0..stage_state.rows() {
                assign_result.push(
                    self.rlc
                        .assign_u256(region, offset + i, rlcs[i])
                        .map(|_| ()),
                );
                assign_result.push(self.lt_gadget.assign(region, offset + i, prev_rlc, rlcs[i]));
                prev_rlc = rlcs[i];
            }
            let assign_result = assign_result.into_iter().collect::<Result<Vec<_>, Error>>();
            assign_result.is_err()
        })?;
        Ok(stage_state.rows())
    }
}
