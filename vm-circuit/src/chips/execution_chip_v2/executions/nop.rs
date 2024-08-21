// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::math_gadgets::lt::LtGadget;
use crate::chips::execution_chip_v2::step_v2::StepState;
use crate::chips::execution_chip_v2::utils::from_bytes::MAX_N_BYTES_INTEGER;
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::utils::cached_region::CachedRegion;
use crate::utils::rlc;
use aptos_move_witnesses::exec_state::ExecutionState;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::Expr;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2_proofs::poly::Rotation;
use types::Field;

#[derive(Clone, Debug)]
pub struct Nop<F> {
    lt_gadget: LtGadget<F, MAX_N_BYTES_INTEGER>,
}

impl<F: Field> InstructionGadgetV2<F> for Nop<F> {
    const NAME: &'static str = "Mul_Div_Mod";
    const OPCODES: &'static [Opcode] = &[Opcode::Mul];
    const EXECUTION_STATE: ExecutionState = ExecutionState::MulDivMod;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.require_in_set(
            "opcode = NOP",
            cb.curr.state.opcode.expr(),
            Self::OPCODES.iter().map(|c| (*c as u64).expr()).collect(),
        );
        cb.require_zero(
            "local_write_version(0) ==0",
            cb.curr.state.local_write_version.expr(),
        );

        let mut lt = None;
        cb.not_first_row(|cb| {
            let cur_rlc = cb.rlc(&[
                cb.curr.state.local_frame_index.expr(),
                cb.curr.state.local_index.expr(),
                cb.curr.state.local_sub_index.expr(),
            ]);
            let prev_step = cb.step_state_at_offset(-1);
            let prev_rlc = cb.rlc(&[
                prev_step.local_frame_index.expr(),
                prev_step.local_index.expr(),
                prev_step.local_sub_index.expr(),
            ]);
            let lt_gadget = LtGadget::<F, MAX_N_BYTES_INTEGER>::construct(cb, prev_rlc, cur_rlc);
            cb.require_true("prev_rlc < cur_rlc", lt_gadget.expr());
            lt = Some(lt_gadget);
        });
        Self {
            lt_gadget: lt.unwrap(),
        }
    }
    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        debug_assert!(stage_state.rows() > 0);

        let randomness = region.challenges().keccak_input();

        let rlcs: Value<Vec<_>> = Value::from_iter((0..stage_state.rows()).map(|i| {
            let local_frame_index = region.get_advice(
                offset + i,
                _step.local_frame_index.get_column_idx(),
                Rotation::cur(),
            );
            let local_index = region.get_advice(
                offset + i,
                _step.local_index.get_column_idx(),
                Rotation::cur(),
            );
            let local_sub_index = region.get_advice(
                offset + i,
                _step.local_sub_index.get_column_idx(),
                Rotation::cur(),
            );
            randomness.map(|r| rlc::generic([local_frame_index, local_index, local_sub_index], r))
        }));
        let sort_rlcs = rlcs.map(|mut l| {
            l.sort();
            l
        });
        sort_rlcs.error_if_known_and(|rlcs| {
            let mut assign_result = vec![self.lt_gadget.assign(region, offset, F::zero(), rlcs[0])];
            for i in 1..stage_state.rows() {
                assign_result.push(
                    self.lt_gadget
                        .assign(region, offset + i, rlcs[i - 1], rlcs[i]),
                );
            }
            let assign_result = assign_result.into_iter().collect::<Result<Vec<_>, Error>>();
            assign_result.is_err()
        })?;

        Ok(stage_state.rows())
    }
}
