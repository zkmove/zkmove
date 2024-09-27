use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::ExtendedSubIndex;
use crate::chips::execution_chip_v2::executions::Membership;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, PC, SP,
};
use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::{
    ConstraintBuilderV2, Transition,
};
use crate::chips::execution_chip_v2::utils::to_field::ToField;
use crate::chips::execution_chip_v2::value::Index;
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utils::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::not;
use halo2_proofs::poly::Rotation;
use halo2_proofs::{circuit::Value, plonk::Error};
use types::Field;

///STAGE_POP_REF_AND_INVALIDATE_OLD
#[derive(Clone, Debug)]
pub struct WriteRefStage1<F> {
    header_sub_index: Cell<F>,
    header_flen_delta: Cell<F>,
    membership_gadget: Membership<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for WriteRefStage1<F> {
    const NAME: &'static str = "WriteRef_Stage1";
    const EXECUTION_STATE: ExecutionState = ExecutionState::WriteRefStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_sub_index = cb.query_cell();
        let header_flen_delta = cb.query_cell();
        let membership_gadget = Membership::construct(cb);
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in OPCODES",
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
            let index = Index::new(
                step_curr.local_frame_index.expr(),
                step_curr.local_index.expr(),
            );
            cb.require_equal(
                format!(
                    "{}, (local_frame_index(0), local_index(0)) == stack_pop_value(0).index",
                    Self::NAME
                ),
                index.expr(),
                step_curr.stack_pop_value.as_reference().index(),
            );
            cb.require_equal(
                format!(
                    "{}, local_sub_index(0) == stack_pop_value(0).sub_index",
                    Self::NAME
                ),
                step_curr.local_sub_index.expr(),
                step_curr.stack_pop_value.as_reference().sub_index(),
            );
            cb.condition(step_curr.local_read_value_header.expr(), |cb| {
                cb.require_equal(
                    format!(
                        "{}, step_counter(0) == local_read_value(0).as_header().f_len",
                        Self::NAME
                    ),
                    step_curr.step_counter.expr(),
                    step_curr.local_read_value.as_header().flen(),
                );
            });
            cb.condition(not::expr(step_curr.local_read_value_header.expr()), |cb| {
                cb.require_equal(
                    format!("{}, step_counter(0) == 1", Self::NAME),
                    step_curr.step_counter.expr(),
                    1u64.expr(),
                );
            });
            cb.require_equal(
                format!("{}, header_sub_index(0) == local_sub_index(0)", Self::NAME),
                header_sub_index.expr(),
                step_curr.local_sub_index.expr(),
            );
            cb.require_equal(
                format!("{}, header_flen_delta(0) == step_counter(0)", Self::NAME),
                header_flen_delta.expr(),
                step_curr.step_counter.expr(),
            );
        });

        cb.not_first_row(|cb| {
            membership_gadget.configure(
                cb,
                header_sub_index.expr(),
                step_curr.local_sub_index.expr(),
            );
            cb.require_no_stack_pop();
        });

        cb.require_write_invalid_value();
        cb.require_equal(
            "local_write_version(0) == clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_no_stack_push();
        cb.require_cell_transition(step_curr.local_frame_index.clone(), Transition::Same);
        cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
        cb.require_cell_transition(header_sub_index.clone(), Transition::Same);

        cb.not_last_row(|cb| {
            cb.require_cell_transition(header_flen_delta.clone(), Transition::Same);
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::WriteRefStage2);
            cb.require_state_transition(vec![
                (PC, Transition::Same),
                (SP, Transition::Delta((-1).expr())),
            ]);
        });

        WriteRefStage1 {
            header_sub_index,
            header_flen_delta,
            membership_gadget,
        }
    }

    fn assign(
        &self,
        step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();
        debug_assert!(!step_state.memory_ops.is_empty());
        let header_sub_index = step_state
            .memory_ops
            .first()
            .unwrap()
            .0
            .as_ref()
            .unwrap()
            .value
            .hi();
        let rows = step_state.memory_ops.len();
        (0..rows)
            .map(|i| {
                self.header_sub_index.assign(
                    region,
                    offset + i,
                    Value::known(F::from_u128(header_sub_index)),
                )?;
                self.header_flen_delta.assign(
                    region,
                    offset + i,
                    Value::known(F::from(rows as u64)),
                )?;
                let local_sub_index = &step_state.memory_ops[i].2.as_ref().unwrap().sub_index;
                self.membership_gadget.assign(
                    region,
                    offset + i,
                    header_sub_index,
                    local_sub_index.clone().into(),
                )
            })
            .try_fold((), |_, res| res)?;
        Ok(rows)
    }
}

///STAGE_POP_NEW_VALUE_AND_WRITE
#[derive(Clone, Debug)]
pub struct WriteRefStage2<F> {
    header_sub_index: Cell<F>,  //NOTICE: must be in the same column as stage 1.
    header_flen_delta: Cell<F>, //NOTICE: must be in the same column as stage 1.
    header_sub_index_ext: ExtendedSubIndex<F, 8>,
    is_zero_header_sub_index: IsZeroGadget<F>,
}
impl<F: Field> InstructionGadgetV2<F> for WriteRefStage2<F> {
    const NAME: &'static str = "WriteRef_Stage2";
    const EXECUTION_STATE: ExecutionState = ExecutionState::WriteRefStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_sub_index = cb.query_cell();
        let header_flen_delta = cb.query_cell();
        let header_sub_index_ext = ExtendedSubIndex::construct(cb, header_sub_index.expr());
        let is_zero_header_sub_index = IsZeroGadget::construct(cb, header_sub_index.expr());
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::WriteRefStage1);

            let header_flen_delta_prev = cb.cell_at_offset(&header_flen_delta, -1).expr();
            cb.condition(step_curr.stack_pop_value_header.expr(), |cb| {
                cb.require_equal(
                    format!(
                        "{}, step_counter(0) == stack_pop_value(0).as_header().f_len",
                        Self::NAME
                    ),
                    step_curr.step_counter.expr(),
                    step_curr.stack_pop_value.as_header().flen(),
                );
            });
            cb.condition(not::expr(step_curr.stack_pop_value_header.expr()), |cb| {
                cb.require_equal(
                    format!("{}, step_counter(0) == 1", Self::NAME),
                    step_curr.step_counter.expr(),
                    1u64.expr(),
                );
            });
            cb.require_equal(
                format!(
                    "{}, header_flen_delta(0) == step_counter(0) - header_flen_delta(-1)",
                    Self::NAME
                ),
                header_flen_delta.expr(),
                step_curr.step_counter.expr() - header_flen_delta_prev.clone(),
            );
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                step_curr.stack_pop_sub_index.expr(),
            );
        });

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );

        cb.require_equal(
            format!(
                "{}, local_sub_index(0) == header_sub_index(0).concat(stack_pop_sub_index(0))",
                Self::NAME
            ),
            step_curr.local_sub_index.expr(),
            header_sub_index_ext.concat(step_curr.stack_pop_sub_index.expr()),
        );

        cb.require_read_invalid_value();

        cb.require_equal(
            format!("{}, local_write_value(0) == stack_pop_value(0)", Self::NAME),
            step_curr.local_write_value.expr(),
            step_curr.stack_pop_value.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value_header(0) == stack_pop_value_header(0)",
                Self::NAME
            ),
            step_curr.local_write_value_header.expr(),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_equal(
            "local_write_version(0) == clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_no_stack_push();

        cb.not_last_row(|cb| {
            cb.require_cell_transition(step_curr.local_frame_index.clone(), Transition::Same);
            cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
            cb.require_cell_transition(header_sub_index.clone(), Transition::Same);
            cb.require_cell_transition(header_flen_delta.clone(), Transition::Same);
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

        cb.last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
            cb.condition(1u64.expr() - is_zero_header_sub_index.expr(), |cb| {
                cb.require_state_transition(vec![(PC, Transition::Same)]);
                cb.require_next_state(ExecutionState::WriteRefStage3);
            });
            cb.condition(is_zero_header_sub_index.expr(), |cb| {
                cb.require_state_transition(vec![(PC, Transition::Delta(1.expr()))]);
            });
        });

        WriteRefStage2 {
            header_sub_index,
            header_flen_delta,
            header_sub_index_ext,
            is_zero_header_sub_index,
        }
    }

    fn assign(
        &self,
        step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();

        let header_sub_index = region.get_advice(
            offset,
            self.header_sub_index.get_column_idx(),
            Rotation(self.header_sub_index.get_rotation() as i32 - 1),
        );
        let header_flen_delta_prev_stage = region.get_advice(
            offset,
            self.header_flen_delta.get_column_idx(),
            Rotation(self.header_flen_delta.get_rotation() as i32 - 1),
        );

        let rows = step_state.memory_ops.len();
        let header_flen_delta = F::from(rows as u64);
        (0..rows)
            .map(|i| {
                self.header_sub_index
                    .assign(region, offset + i, Value::known(header_sub_index))?;
                self.header_flen_delta.assign(
                    region,
                    offset + i,
                    Value::known(header_flen_delta - header_flen_delta_prev_stage),
                )?;
                self.is_zero_header_sub_index
                    .assign(region, offset + i, header_sub_index)?;
                self.header_sub_index_ext
                    .assign(region, offset + i, header_sub_index)
            })
            .try_fold((), |_, res| res)?;
        Ok(rows)
    }
}

///STAGE_UPDATE_PARENT
#[derive(Clone, Debug)]
pub struct WriteRefStage3<F> {
    header_sub_index: Cell<F>, //NOTICE: must be in the same column as prev stage.
    header_flen_delta: Cell<F>, //NOTICE: must be in the same column as prev stage.
    header_sub_index_ext: ExtendedSubIndex<F, 8>,
    is_zero_gadget: IsZeroGadget<F>,
}
impl<F: Field> InstructionGadgetV2<F> for WriteRefStage3<F> {
    const NAME: &'static str = "WriteRef_Stage3";
    const EXECUTION_STATE: ExecutionState = ExecutionState::WriteRefStage3;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_sub_index = cb.query_cell(); //NOTICE: must be in the same column as stage 2.
        let header_flen_delta = cb.query_cell(); //NOTICE: must be in the same column as stage 2.
        let header_sub_index_prev = cb.cell_at_offset(&header_sub_index, -1).expr();
        let header_sub_index_ext = ExtendedSubIndex::construct(cb, header_sub_index_prev.clone());
        let is_zero_gadget =
            IsZeroGadget::construct(cb, header_sub_index_prev - header_sub_index.expr());
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::WriteRefStage2);

            let header_flen_delta_prev = cb.cell_at_offset(&header_flen_delta, -1).expr();
            cb.require_equal(
                format!(
                    "{}, header_flen_delta(0) == header_flen_delta(-1)",
                    Self::NAME
                ),
                header_flen_delta.expr(),
                header_flen_delta_prev,
            );
            let local_frame_index_prev = cb.cell_at_offset(&step_curr.local_frame_index, -1).expr();
            cb.require_equal(
                format!(
                    "{}, local_frame_index(0) == local_frame_index(-1)",
                    Self::NAME
                ),
                step_curr.local_frame_index.expr(),
                local_frame_index_prev,
            );
            let local_index_prev = cb.cell_at_offset(&step_curr.local_index, -1).expr();
            cb.require_equal(
                format!("{}, local_index(0) == local_index(-1)", Self::NAME),
                step_curr.local_index.expr(),
                local_index_prev,
            );
        });

        cb.require_no_stack_pop();
        cb.require_no_stack_push();

        cb.require_equal(
            format!(
                "{}, header_sub_index(0) == header_sub_index(-1).parent",
                Self::NAME
            ),
            header_sub_index.expr(),
            header_sub_index_ext.get_parent_sub_index(),
        );
        cb.require_zero(
            "header_sub_index(0) != header_sub_index(-1)",
            is_zero_gadget.expr(),
        );
        cb.require_equal(
            format!("{}, local_sub_index(0) == header_sub_index(0)", Self::NAME),
            step_curr.local_sub_index.expr(),
            header_sub_index.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value(0).as_header().flen == local_read_value(0).as_header().flen + header_flen_delta(0)",
                Self::NAME
            ),
            step_curr.local_write_value.as_header().flen(),
            step_curr.local_read_value.as_header().flen() + header_flen_delta.expr(),
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
            format!(
                "{}, local_write_value_invalid(0) == local_read_value_invalid(0)",
                Self::NAME
            ),
            step_curr.local_write_value_invalid.expr(),
            step_curr.local_read_value_invalid.expr(),
        );
        cb.require_equal(
            "local_write_version(0) == clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_state_transition(vec![(SP, Transition::Same)]);

        cb.not_last_row(|cb| {
            cb.require_cell_transition(header_flen_delta.clone(), Transition::Same);
            cb.require_cell_transition(step_curr.local_frame_index.clone(), Transition::Same);
            cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
        });

        cb.last_row(|cb| {
            cb.require_zero("header_sub_index(0) == 0", header_sub_index.expr());
            cb.require_state_transition(vec![(PC, Transition::Delta(1.expr()))]);
        });

        WriteRefStage3 {
            header_sub_index,
            header_flen_delta,
            header_sub_index_ext,
            is_zero_gadget,
        }
    }

    fn assign(
        &self,
        step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();

        let header_sub_index_prev_stage = region.get_advice(
            offset,
            self.header_sub_index.get_column_idx(),
            Rotation(self.header_sub_index.get_rotation() as i32 - 1),
        );
        let header_flen_delta_prev_stage = region.get_advice(
            offset,
            self.header_flen_delta.get_column_idx(),
            Rotation(self.header_flen_delta.get_rotation() as i32 - 1),
        );

        let rows = step_state.memory_ops.len();
        (0..rows)
            .map(|i| {
                let local_sub_index = &step_state.memory_ops[i].2.as_ref().unwrap().sub_index;
                self.header_sub_index.assign(
                    region,
                    offset + i,
                    Value::known(local_sub_index.to_field()),
                )?;

                self.header_flen_delta.assign(
                    region,
                    offset + i,
                    Value::known(header_flen_delta_prev_stage),
                )?;

                let header_sub_index_prev = if i == 0 {
                    header_sub_index_prev_stage
                } else {
                    step_state.memory_ops[i - 1]
                        .2
                        .as_ref()
                        .unwrap()
                        .sub_index
                        .to_field()
                };
                let header_sub_index: F = local_sub_index.to_field();
                self.is_zero_gadget.assign(
                    region,
                    offset + i,
                    header_sub_index_prev - header_sub_index,
                )?;
                self.header_sub_index_ext
                    .assign(region, offset + i, header_sub_index_prev)
            })
            .try_fold((), |_, res| res)?;
        Ok(rows)
    }
}
