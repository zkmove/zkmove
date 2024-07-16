use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::{ExecutionState, DEPTH_POW_OF_ONE_LEVEL};
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::step_state::ExecStepState;
use gadgets::util::{and, not};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2_proofs::poly::Rotation;
use itertools::Itertools;
use std::collections::HashMap;

use types::Field;

#[derive(Clone, Debug)]
pub struct Pack<F, const VEC_PACK: bool> {
    field_index: Cell<F>,
    field_counter: Cell<F>,
    is_zero_stack_pop_sub_index: IsZeroGadget<F>,
    is_zero_num_field: IsZeroGadget<F>,
    last_row: IsZeroGadget<F>,
    last_row_of_field: IsZeroGadget<F>,
}
impl<F: Field, const VEC_PACK: bool> InstructionGadgetV2<F> for Pack<F, VEC_PACK> {
    const NAME: &'static str = if VEC_PACK { "VecPack" } else { "Pack" };
    const OPCODE: Opcode = if VEC_PACK {
        Opcode::VecPack
    } else {
        Opcode::Pack
    };
    const EXECUTION_STATE: ExecutionState = if VEC_PACK {
        ExecutionState::VecPack
    } else {
        ExecutionState::Pack
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let field_index = cb.query_cell(); //TODO: query byte for each LIMB_BITS
        let field_counter = cb.query_cell();
        let is_zero_stack_pop_sub_index =
            IsZeroGadget::construct(cb, cb.curr.state.stack_pop_sub_index.expr());
        let is_zero_num_field = IsZeroGadget::construct(cb, cb.curr.state.aux0.expr());
        let last_row = IsZeroGadget::construct(cb, cb.curr.state.step_counter.expr() - 1u64.expr());
        let last_row_of_field = IsZeroGadget::construct(cb, field_counter.expr() - 1u64.expr());
        let step_curr = cb.curr.state.clone();
        let step_next = cb.step_state_at_offset(1);
        let field_index_next = cb.cell_at_offset(&field_index, 1);
        let num_field = step_curr.aux0.expr();

        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );
            cb.require_equal(
                format!(
                    "{}, stack_push_index(0) == sp(0) - num_field + 1",
                    Self::NAME
                ),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr() - num_field.clone() + 1u64.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );
            cb.require_equal(
                format!(
                    "{}, stack_push_value(0).as_header().len() == num_field",
                    Self::NAME
                ),
                step_curr.stack_push_value.as_header().len(),
                num_field.clone(),
            );
            cb.require_equal(
                format!(
                    "{}, stack_push_value(0).as_header().flen() == step_counter(0)",
                    Self::NAME
                ),
                step_curr.stack_push_value.as_header().flen(),
                step_curr.step_counter.expr(),
            );
            cb.require_true(
                format!("{}, stack_push_value_header(0) == true", Self::NAME),
                step_curr.stack_push_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            cb.require_no_stack_pop();
            cb.require_no_local_op();

            cb.condition(not::expr(is_zero_num_field.expr()), |cb| {
                cb.require_equal(
                    format!("{}, field_index(1) == aux0(0)", Self::NAME),
                    field_index_next.expr(),
                    step_curr.aux0.expr(),
                );
                cb.require_equal(
                    format!("{}, stack_pop_index(1) == sp(0)", Self::NAME),
                    step_next.stack_pop_index.expr(),
                    step_curr.sp.expr(),
                );
                cb.require_zero(
                    format!("{}, stack_pop_sub_index(1) == 0", Self::NAME),
                    step_next.stack_pop_sub_index.expr(),
                );
            });
            cb.condition(is_zero_num_field.expr(), |cb| {
                cb.require_equal(
                    format!("{}, step_counter(0) == 1", Self::NAME),
                    step_curr.step_counter.expr(),
                    1u64.expr(),
                );
            });
        });

        cb.not_first_row(|cb| {
            cb.condition(is_zero_stack_pop_sub_index.expr(), |cb| {
                //if is_simple then 'field_counter(0)' must equal to 1
                cb.require_zero(
                    format!("{}, is_simple * (field_counter(0) - 1)", Self::NAME),
                    (1u64.expr() - step_curr.stack_pop_value_header.expr())
                        * (field_counter.expr() - 1u64.expr()),
                );

                //if is_header then 'field_counter(0)' must equal to 'stack_pop_value(0).flen'
                cb.require_zero(
                    format!(
                        "{}, is_header * (field_counter(0) - stack_pop_value(0).as_header().flen) == 0",
                        Self::NAME
                    ),
                    step_curr.stack_pop_value_header.expr()
                        * (field_counter.expr() - step_curr.stack_pop_value.as_header().flen()),
                );
            });

            cb.require_equal(
                format!(
                    "{}, stack_push_index(0) == sp(0) - num_field + 1",
                    Self::NAME
                ),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr() - num_field.clone() + 1u64.expr(),
            );
            cb.require_equal(
                format!(
                    "{}, stack_push_sub_index(0) == stack_pop_sub_index(0) * DEPTH_POW_OF_ONE_LEVEL + field_index(0)",
                    Self::NAME
                ),
                step_curr.stack_push_sub_index.expr(),
                step_curr.stack_pop_sub_index.expr() * DEPTH_POW_OF_ONE_LEVEL.expr() + field_index.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_value(0) == stack_pop_value(0)", Self::NAME),
                step_curr.stack_push_value.expr(),
                step_curr.stack_pop_value.expr(),
            );
            cb.require_equal(
                format!(
                    "{}, stack_push_value_header(0) == stack_pop_value_header(0)",
                    Self::NAME
                ),
                step_curr.stack_push_value_header.expr(),
                step_curr.stack_pop_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            cb.require_no_local_op();

            cb.condition(and::expr([not::expr(last_row.expr()), last_row_of_field.expr()]), |cb| {
                cb.require_cell_transition(field_index.clone(), Transition::Delta((-1).expr()));
                cb.require_cell_transition(step_curr.stack_pop_index.clone(), Transition::Delta((-1).expr()));
                cb.require_cell_transition(step_curr.stack_pop_sub_index, Transition::To(0.expr()));
            });
            cb.condition(and::expr([not::expr(last_row.expr()), not::expr(last_row_of_field.expr())]), |cb| {
                cb.require_cell_transition(field_index.clone(), Transition::Same);
                cb.require_cell_transition(field_counter.clone(), Transition::Delta((-1).expr()));
                cb.require_cell_transition(step_curr.stack_pop_index, Transition::Same);
            });
        });

        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

        cb.last_row(|cb| {
            cb.condition(not::expr(is_zero_num_field.expr()), |cb| {
                // all fields processed
                cb.require_equal(
                    format!("{}, field_index(0) == 1", Self::NAME),
                    field_index.expr(),
                    1u64.expr(),
                );
                cb.require_equal(
                    format!("{}, field_counter(0) == 1", Self::NAME),
                    field_counter.expr(),
                    1u64.expr(),
                );
            });

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Delta(1.expr())),
                (SP, Transition::To(step_curr.stack_push_index.expr())),
            ]);
        });

        Pack {
            field_index,
            field_counter,
            is_zero_stack_pop_sub_index,
            is_zero_num_field,
            last_row,
            last_row_of_field,
        }
    }

    fn assign(
        &self,
        step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        start_offset: usize,
        step_state: &ExecStepState,
    ) -> Result<usize, Error> {
        debug_assert!(!step_state.memory_ops.is_empty());
        let cur_step_counter = region.get_advice(
            start_offset,
            step.step_counter.get_column_idx(),
            Rotation::cur(),
        );
        debug_assert!(cur_step_counter == F::from(step_state.memory_ops.len() as u64));
        let step_counter = step_state.memory_ops.len(); // TODO: fetch from Step
        let field_counters = step_state
            .memory_ops
            .iter()
            .skip(1)
            .counts_by(|item| item.0.as_ref().unwrap().index);
        let num_field = field_counters.len();

        self.field_index
            .assign(region, start_offset, Value::unknown())?;
        self.field_counter
            .assign(region, start_offset, Value::unknown())?;
        self.last_row_of_field
            .assign(region, start_offset, F::zero())?;

        self.is_zero_stack_pop_sub_index
            .assign(region, start_offset, F::zero())?;
        self.is_zero_num_field
            .assign(region, start_offset, F::from(num_field as u64))?;
        self.last_row
            .assign(region, start_offset, cur_step_counter - F::one())?;

        let mut args = HashMap::new();
        for (stack_index, d) in step_state
            .memory_ops
            .clone()
            .into_iter()
            .enumerate()
            .skip(1)
            .group_by(|(i, memory_ops)| memory_ops.0.as_ref().unwrap().index)
            .into_iter()
        {
            let old = args.insert(stack_index, d.collect::<Vec<_>>());
            debug_assert!(old.is_none());
        }
        debug_assert_eq!(args.len(), num_field);
        let mut field_index = num_field as u64;
        for arg in args.into_values() {
            let mut field_counter = arg.len() as u64;
            for (i, memory_op) in arg {
                let stack_pop = memory_op.0.as_ref().unwrap();
                self.field_index.assign(
                    region,
                    start_offset + i,
                    Value::known(F::from(field_index)),
                )?;
                self.field_counter.assign(
                    region,
                    start_offset + i,
                    Value::known(F::from(field_counter)),
                )?;
                let stack_pop_sub_index = region.get_advice(
                    start_offset + i,
                    step.stack_pop_sub_index.get_column_idx(),
                    Rotation::cur(),
                );
                self.is_zero_stack_pop_sub_index.assign(
                    region,
                    start_offset + i,
                    stack_pop_sub_index,
                )?;
                self.is_zero_num_field.assign(
                    region,
                    start_offset + i,
                    F::from(num_field as u64),
                )?;
                let cur_step_counter = region.get_advice(
                    start_offset + i,
                    step.step_counter.get_column_idx(),
                    Rotation::cur(),
                );
                self.last_row
                    .assign(region, start_offset + i, cur_step_counter - F::one())?;
                self.last_row_of_field
                    .assign(region, start_offset + i, F::from(field_counter))?;

                field_counter -= 1;
            }

            field_index -= 1;
        }
        Ok(step_state.memory_ops.len())
    }
}
