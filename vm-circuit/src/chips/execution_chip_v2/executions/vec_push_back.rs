use crate::chips::execution_chip_v2::executions::{
    ExecutionState, ExtendedSubIndex, DEPTH_POW_OF_ONE_LEVEL,
};
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, AUX0, AUX1, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, OPCODE, PC, SP,
};
use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::{
    ConstraintBuilderV2, Transition,
};
use crate::chips::execution_chip_v2::value::{Index, WordU16};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;

use crate::chips::execution_chip_v2::math_gadgets::range_check::RangeCheckGadget;
use crate::chips::execution_chip_v2::utils::pow_of_two_expr;
use crate::chips::execution_chip_v2::utils::to_field::ToField;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use aptos_move_witnesses::types::sub_index::SubIndex;
use aptos_move_witnesses::types::value_header::ValueHeader;
use gadgets::util::Expr;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2_proofs::poly::Rotation;
use types::Field;

/// pop vector_ref from stack and update parent from up to bottom
#[derive(Clone)]
pub struct VecPushBackStage1<F> {
    vector_sub_index: Cell<F>,
    extended_local_sub_index_of_next_row: ExtendedSubIndex<F, 8>,
    vector_origin_len: WordU16<F>,
    is_ori_len_max_u16: IsZeroGadget<F>,
    is_zero_gadget: IsZeroGadget<F>,
}
impl<F: Field> VecPushBackStage1<F> {
    const NEXT_STATE: ExecutionState = ExecutionState::VecPushBackStage2;
}
impl<F: Field> InstructionGadgetV2<F> for VecPushBackStage1<F> {
    const NAME: &'static str = "VecPushBackStage1";
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecPushBackStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_next = cb.step_state_at_offset(1);
        let step_prev = cb.step_state_at_offset(-1);
        let vector_sub_index = cb.query_cell();
        let next_local_sub_index = step_next.local_sub_index.clone();
        let extended_local_sub_index_of_next_row =
            ExtendedSubIndex::construct_without_configure(cb, next_local_sub_index.expr());
        let is_zero_gadget = IsZeroGadget::construct_without_configure(
            cb,
            step_curr.local_sub_index.expr() - next_local_sub_index.expr(),
        );

        // make sure len is in range u16, and len != u16::MAX
        let vector_origin_len = WordU16::construct(cb);
        let max_u16 = pow_of_two_expr(16) - 1u64.expr();
        let is_ori_len_max_u16 =
            IsZeroGadget::construct_without_configure(cb, max_u16 - vector_origin_len.expr());

        cb.require_no_stack_push();

        cb.last_row(|cb| {
            cb.require_next_state(Self::NEXT_STATE);
        });

        // -- local op constraints
        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in OPCODES",
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr() - 1.expr(),
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
                    "{}, vector_sub_index(0) == stack_pop_value(0).sub_index",
                    Self::NAME
                ),
                vector_sub_index.expr(),
                step_curr.stack_pop_value.as_reference().sub_index(),
            );
            cb.require_zero("local_sub_index(0)==0", step_curr.local_sub_index.expr());
        });

        cb.not_first_row(|cb| {
            cb.require_no_stack_pop();

            cb.require_equal(
                "local_frame_index(0) == local_frame_index(-1)",
                step_curr.local_frame_index.expr(),
                step_prev.local_frame_index.expr(),
            );
            cb.require_equal(
                "local_index(0) == local_index(-1)",
                step_curr.local_index.expr(),
                step_prev.local_index.expr(),
            );
            let prev_vector_sub_index = cb.cell_at_offset(&vector_sub_index, -1);
            cb.require_equal(
                "vector_sub_index(0) == vector_sub_index(-1)",
                vector_sub_index.expr(),
                prev_vector_sub_index.expr(),
            );
        });

        cb.not_last_row(|cb| {
            extended_local_sub_index_of_next_row.configure(cb);
            cb.require_equal(
                "local_sub_index(0) == local_sub_index(1).parent()",
                step_curr.local_sub_index.expr(),
                extended_local_sub_index_of_next_row.get_parent_sub_index(),
            );
            is_zero_gadget.configure(cb, "iszero(local_sub_index(0)-local_sub_index(1))");
            cb.require_zero(
                "local_sub_index(0) != local_sub_index(1)",
                is_zero_gadget.expr(),
            )
        });
        cb.last_row(|cb| {
            cb.require_equal(
                "local_sub_index(0) == vector_sub_index(0)",
                step_curr.local_sub_index.expr(),
                vector_sub_index.expr(),
            );
        });
        cb.require_true(
            "local_read_value_header(0) == true",
            step_curr.local_read_value_header.expr(),
        );
        cb.require_zero(
            "local_read_value_invalid(0)==false",
            step_curr.local_read_value_invalid.expr(),
        );
        cb.require_true(
            "local_write_value_header(0) == true",
            step_curr.local_write_value_header.expr(),
        );
        cb.require_zero(
            "local_write_value_invalid(0)==false",
            step_curr.local_write_value_invalid.expr(),
        );
        cb.require_equal(
            "local_write_version(0) == clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );

        cb.not_last_row(|cb| {
                cb.require_equal(
                    "local_write_value(0).as_header().flen - local_read_value(0).as_header().flen
                    == local_write_value(1).as_header().flen - local_read_value(1).as_header().flen",
                    step_curr.local_write_value.as_header().flen() - step_curr.local_read_value.as_header().flen(),
                    step_next.local_write_value.as_header().flen() - step_next.local_read_value.as_header().flen(),
                );
                cb.require_equal(
                    "local_read_value(0).as_header().len == local_write_value(0).as_header().len",
                    step_curr.local_read_value.as_header().len(),
                    step_curr.local_write_value.as_header().len(),
                );
            });
        cb.last_row(|cb| {
                cb.require_equal(
                    "local_read_value(0).as_header().flen + step_counter(1) == local_write_value(0).as_header().flen",
                    step_curr.local_read_value.as_header().flen() + step_next.step_counter.expr(),
                    step_curr.local_write_value.as_header().flen(),
                );
                cb.require_equal(
                    "local_read_value(0).as_header().len + 1 == local_write_value(0).as_header().len",
                    step_curr.local_read_value.as_header().len() + 1u64.expr(),
                    step_curr.local_write_value.as_header().len()
                );
                cb.require_equal("vector_origin_len(0) == local_read_value(0).as_header().len", step_curr.local_read_value.as_header().len(), vector_origin_len.expr());
            is_ori_len_max_u16.configure(cb, "2^16-1 - vector_origin_len(0)");
            cb.require_zero("vector_origin_len(0) != 2^16-1",  is_ori_len_max_u16.expr());
        });

        cb.require_state_transition(
            [PC, OPCODE, AUX0, AUX1, SP]
                .into_iter()
                .map(|s| (s, Transition::Same))
                .collect(),
        );

        Self {
            vector_sub_index,
            extended_local_sub_index_of_next_row,
            vector_origin_len,
            is_ori_len_max_u16,
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
        debug_assert_eq!(stage_state.step_states.len(), 1);

        let step_state = stage_state.step_states.first().unwrap();

        let vec_ref_pop = step_state.memory_ops.first().unwrap().0.as_ref().unwrap();
        let vector_sub_index = vec_ref_pop.sub_index.to_field();

        let last_header_local_op = step_state.memory_ops.last().unwrap().2.as_ref().unwrap();

        let vector_origin_len = ValueHeader::from(last_header_local_op.read_value.clone()).len;

        for i in 0..stage_state.rows() {
            self.vector_sub_index
                .assign(region, offset + i, Value::known(vector_sub_index))?;
            // last row
            if i == stage_state.rows() - 1 {
                self.extended_local_sub_index_of_next_row
                    .assign(region, offset + i, F::ZERO)?;

                self.vector_origin_len
                    .assign(region, offset + i, vector_origin_len)?;
                self.is_ori_len_max_u16.assign(
                    region,
                    offset + i,
                    F::from(u16::MAX as u64) - F::from(vector_origin_len as u64),
                )?;
                self.is_zero_gadget.assign(region, offset + i, F::ZERO)?;
            } else {
                let next_local_sub_index = step_state.memory_ops[i + 1]
                    .2
                    .as_ref()
                    .unwrap()
                    .sub_index
                    .clone();
                self.extended_local_sub_index_of_next_row.assign(
                    region,
                    offset + i,
                    next_local_sub_index.to_field(),
                )?;
                self.vector_origin_len.assign(region, offset + i, 0)?;
                self.is_ori_len_max_u16
                    .assign(region, offset + i, F::ZERO)?;
                let local_sub_index = step_state.memory_ops[i]
                    .2
                    .as_ref()
                    .unwrap()
                    .sub_index
                    .clone();
                self.is_zero_gadget.assign(
                    region,
                    offset + i,
                    <SubIndex as ToField<F>>::to_field(&local_sub_index)
                        - <SubIndex as ToField<F>>::to_field(&next_local_sub_index),
                )?;
            }
        }
        Ok(stage_state.rows())
    }
}

/// move value from stack to local
#[derive(Clone)]
pub struct VecPushBackStage2<F> {
    vector_sub_index: Cell<F>,
    extended_vector_sub_index: ExtendedSubIndex<F, 8>,
    vector_origin_len: WordU16<F>,
}
impl<F: Field> VecPushBackStage2<F> {
    const PREV_STATE: ExecutionState = ExecutionState::VecPushBackStage1;
}
impl<F: Field> InstructionGadgetV2<F> for VecPushBackStage2<F> {
    const NAME: &'static str = "VecPushBackStage2";
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecPushBackStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let vector_sub_index = cb.query_cell();
        let extended_vector_sub_index = ExtendedSubIndex::construct(cb, vector_sub_index.expr());
        let vector_origin_len = WordU16::construct(cb);

        cb.require_no_stack_push();

        cb.first_row(|cb| {
            cb.require_prev_state(Self::PREV_STATE);
        });
        let prev_vector_sub_index = cb.cell_at_offset(&vector_sub_index, -1);
        cb.require_equal(
            "vector_sub_index(0) == vector_sub_index(-1)",
            vector_sub_index.expr(),
            prev_vector_sub_index.expr(),
        );
        let prev_vector_origin_len = cb.cells_at_offset(vector_origin_len.cells(), -1);
        cb.require_equal(
            "vector_origin_len(0) == vector_origin_len(-1)",
            vector_origin_len.expr(),
            WordU16::new(prev_vector_origin_len).expr(),
        );

        cb.require_equal(
            "local_frame_index(0) == local_frame_index(-1)",
            step_curr.local_frame_index.expr(),
            step_prev.local_frame_index.expr(),
        );
        cb.require_equal(
            "local_index(0) == local_index(-1)",
            step_curr.local_index.expr(),
            step_prev.local_index.expr(),
        );
        cb.require_equal(
            "local_sub_index(0)
            == extend_vector_sub_index.concat(vector_origin_len(0)+1 + stack_pop_sub_index(0) << 16)",
            step_curr.local_sub_index.expr(),
            extended_vector_sub_index.concat(
                (vector_origin_len.expr()+1u64.expr())
                    + step_curr.stack_pop_sub_index.expr() * DEPTH_POW_OF_ONE_LEVEL.expr(),
            ),
        );
        cb.first_row(|cb| {
            cb.condition(step_curr.local_write_value_header.expr(), |cb| {
                cb.require_equal(
                    format!(
                        "{}, step_counter(0) == local_write_value(0).as_header().flen",
                        Self::NAME
                    ),
                    step_curr.step_counter.expr(),
                    step_curr.local_write_value.as_header().flen(),
                );
            });
            cb.condition(
                1u64.expr() - step_curr.local_write_value_header.expr(),
                |cb| {
                    cb.require_equal(
                        "step_counter(0)==1",
                        step_curr.step_counter.expr(),
                        1.expr(),
                    );
                },
            );
        });
        cb.require_true(
            "local_read_value_invalid(0) == true",
            step_curr.local_read_value_invalid.expr(),
        );
        cb.require_zero(
            "local_write_value_invalid(0) == false",
            step_curr.local_write_value_invalid.expr(),
        );
        cb.require_equal(
            "local_write_version(0) == clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );

        // --- stack pop constraints
        cb.require_equal(
            "stack_pop_index(0) == sp(0)",
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        // sub_index at first row must be zero
        cb.first_row(|cb| {
            cb.require_zero(
                "stack_pop_sub_index(0)==0",
                step_curr.stack_pop_sub_index.expr(),
            );
        });
        cb.require_equal(
            "stack_pop_value(0)==local_write_value(0)",
            step_curr.stack_pop_value.expr(),
            step_curr.local_write_value.expr(),
        );
        cb.require_equal(
            "stack_pop_value_header(0)==local_write_value_header(0)",
            step_curr.stack_pop_value_header.expr(),
            step_curr.local_write_value_header.expr(),
        );

        // next

        cb.not_last_row(|cb| {
            cb.require_state_transition(
                [PC, OPCODE, AUX0, AUX1, SP]
                    .into_iter()
                    .map(|s| (s, Transition::Same))
                    .collect(),
            );
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![
                (PC, Transition::Delta(1.expr())),
                (SP, Transition::Delta((-2).expr())),
            ]);
        });
        Self {
            vector_sub_index,
            extended_vector_sub_index,
            vector_origin_len,
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
        let vector_sub_index = region.get_advice(
            offset,
            self.vector_sub_index.get_column_idx(),
            Rotation::prev(),
        );
        let vector_origin_len_lo = region.get_advice(
            offset,
            self.vector_origin_len.lo().get_column_idx(),
            Rotation::prev(),
        );
        let vector_origin_len_hi = region.get_advice(
            offset,
            self.vector_origin_len.hi().get_column_idx(),
            Rotation::prev(),
        );
        for i in 0..stage_state.rows() {
            self.vector_origin_len.assign_with_fe(
                region,
                offset + i,
                vector_origin_len_lo,
                vector_origin_len_hi,
            )?;
            self.vector_sub_index
                .assign(region, offset + i, Value::known(vector_sub_index))?;
            self.extended_vector_sub_index
                .assign(region, offset + i, vector_sub_index)?;
        }
        Ok(stage_state.rows())
    }
}
