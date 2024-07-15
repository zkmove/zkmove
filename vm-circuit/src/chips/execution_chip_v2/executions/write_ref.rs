use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::ExtendedSubIndex;
use crate::chips::execution_chip_v2::executions::MembershipGadget;
use crate::chips::execution_chip_v2::executions::SubIndexDepth;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::value::Index;
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::step_state::ExecStepState;
use aptos_move_witnesses::step_state::SubIndex;
use aptos_move_witnesses::utils::SubIndexUtils;
use gadgets::util::not;
use halo2_proofs::poly::Rotation;
use halo2_proofs::{circuit::Value, plonk::Error};
use types::Field;

///STAGE_POP_REF_AND_INVALIDATE_OLD
#[derive(Clone, Debug)]
pub struct WriteRefStage1<F: Field> {
    header_sub_index: Cell<F>,
    header_flen_delta: Cell<F>,
    membership_gadget: MembershipGadget<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for WriteRefStage1<F> {
    const NAME: &'static str = "WriteRef_Stage1";
    const OPCODE: Opcode = Opcode::WriteRef;
    const EXECUTION_STATE: ExecutionState = ExecutionState::WriteRefStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_sub_index = cb.query_cell();
        let header_flen_delta = cb.query_cell();
        let membership_gadget = MembershipGadget::<_, 8>::construct(cb);
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
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
                Self::NAME,
            );
            cb.require_no_stack_pop();
        });

        //TODO: local_read_version(0) < clk(0);
        cb.require_write_invalid_value();
        cb.require_equal(
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
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
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
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
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        step_state: &ExecStepState,
    ) -> Result<usize, Error> {
        let header_sub_index = &step_state.memory_ops[0].0.as_ref().unwrap().sub_index;
        let rows = step_state.memory_ops.len();
        (0..rows)
            .map(|i| {
                self.header_sub_index.assign(
                    region,
                    offset + i,
                    Value::known(header_sub_index.to_fe()),
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
                    header_sub_index.into_u128(),
                    local_sub_index.into_u128(),
                )
            })
            .try_fold((), |_, res| res)?;
        Ok(rows)
    }
}

///STAGE_POP_NEW_VALUE_AND_WRITE
#[derive(Clone, Debug)]
pub struct WriteRefStage2<F: Field> {
    header_sub_index: Cell<F>,  //NOTICE: must be in the same column as stage 1.
    header_flen_delta: Cell<F>, //NOTICE: must be in the same column as stage 1.
    header_sub_index_ext: ExtendedSubIndex<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for WriteRefStage2<F> {
    const NAME: &'static str = "WriteRef_Stage2";
    const OPCODE: Opcode = Opcode::WriteRef;
    const EXECUTION_STATE: ExecutionState = ExecutionState::WriteRefStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_sub_index = cb.query_cell();
        let header_flen_delta = cb.query_cell();
        let header_sub_index_ext =
            ExtendedSubIndex::<_, 8>::construct(cb, Self::NAME, header_sub_index.expr());
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
            header_sub_index_ext.concat_sub_index(step_curr.stack_pop_sub_index.expr()),
        );

        cb.require_read_invalid_value();
        // TODO: local_read_version(0) < clk(0);

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
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
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
            cb.require_next_state(ExecutionState::WriteRefStage3);
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Delta((-1).expr())),
                (PC, Transition::Same),
            ]);
        });

        WriteRefStage2 {
            header_sub_index,
            header_flen_delta,
            header_sub_index_ext,
        }
    }

    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        step_state: &ExecStepState,
    ) -> Result<usize, Error> {
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
                self.header_sub_index_ext.assign(
                    region,
                    offset + i,
                    header_sub_index.get_lower_128(),
                    SubIndex::from_u128(header_sub_index.get_lower_128()).len(),
                )
            })
            .try_fold((), |_, res| res)?;
        Ok(rows)
    }
}

///STAGE_UPDATE_PARENT
#[derive(Clone, Debug)]
pub struct WriteRefStage3<F: Field> {
    header_sub_index: Cell<F>, //NOTICE: must be in the same column as prev stage.
    header_flen_delta: Cell<F>, //NOTICE: must be in the same column as prev stage.
    header_sub_index_depth: SubIndexDepth<F, 8>,
    header_sub_index_ext: ExtendedSubIndex<F, 8>,
}
impl<F: Field> InstructionGadgetV2<F> for WriteRefStage3<F> {
    const NAME: &'static str = "WriteRef_Stage3";
    const OPCODE: Opcode = Opcode::WriteRef;
    const EXECUTION_STATE: ExecutionState = ExecutionState::WriteRefStage3;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_sub_index = cb.query_cell(); //NOTICE: must be in the same column as stage 2.
        let header_flen_delta = cb.query_cell(); //NOTICE: must be in the same column as stage 2.
        let header_sub_index_prev = cb.cell_at_offset(&header_sub_index, -1).expr();
        let header_sub_index_depth =
            SubIndexDepth::<_, 8>::construct(cb, header_sub_index_prev.clone(), Self::NAME);
        let header_sub_index_ext =
            ExtendedSubIndex::construct(cb, Self::NAME, header_sub_index_prev.clone());
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::WriteRefStage2);

            // bug: redundant constraint, clean me
            // cb.require_equal(
            //     format!(
            //         "{}, header_sub_index(0) == header_sub_index(-1)",
            //         Self::NAME
            //     ),
            //     header_sub_index.expr(),
            //     header_sub_index_prev,
            // );
            cb.require_equal(
                format!(
                    "{}, step_counter(0) == header_sub_index(-1).depth()",
                    Self::NAME
                ),
                step_curr.step_counter.expr(),
                header_sub_index_depth.expr(),
            );
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

        cb.require_equal(
            format!(
                "{}, header_sub_index(0) == header_sub_index(-1).parent",
                Self::NAME
            ),
            header_sub_index.expr(),
            header_sub_index_ext.get_parent_sub_index(),
        );
        //TODO: local_read_version(0) < clk(0);
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
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
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
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Same),
            ]);
        });

        WriteRefStage3 {
            header_sub_index,
            header_flen_delta,
            header_sub_index_depth,
            header_sub_index_ext,
        }
    }

    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        step_state: &ExecStepState,
    ) -> Result<usize, Error> {
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
                    Value::known(local_sub_index.to_fe()),
                )?;

                self.header_flen_delta.assign(
                    region,
                    offset + i,
                    Value::known(header_flen_delta_prev_stage),
                )?;

                let header_sub_index_prev = if i == 0 {
                    header_sub_index_prev_stage.get_lower_128()
                } else {
                    step_state.memory_ops[i - 1]
                        .2
                        .as_ref()
                        .unwrap()
                        .sub_index
                        .into_u128()
                };
                self.header_sub_index_depth
                    .assign(region, offset + i, header_sub_index_prev)?;
                self.header_sub_index_ext.assign(
                    region,
                    offset + i,
                    header_sub_index_prev,
                    SubIndex::from_u128(header_sub_index_prev).len(),
                )
            })
            .try_fold((), |_, res| res)?;
        Ok(rows)
    }
}
