use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::{
    ExecutionState, MembershipGadget, DEPTH_POW_OF_ONE_LEVEL,
};
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::step_state::StageState;
use aptos_move_witnesses::utils::SubIndexUtils;
use gadgets::util::not;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2_proofs::poly::Rotation;
use types::Field;

#[derive(Clone, Debug)]
pub struct UnpackStage1<F, const VEC_UNPACK: bool> {
    field_index: Cell<F>,
    is_zero_num_field: IsZeroGadget<F>,
}

impl<F: Field, const VEC_UNPACK: bool> InstructionGadgetV2<F> for UnpackStage1<F, VEC_UNPACK> {
    const NAME: &'static str = if VEC_UNPACK {
        "VecUnpackStage1"
    } else {
        "UnpackStage1"
    };
    const OPCODE: Opcode = if VEC_UNPACK {
        Opcode::VecUnpack
    } else {
        Opcode::Unpack
    };
    const EXECUTION_STATE: ExecutionState = if VEC_UNPACK {
        ExecutionState::VecUnpackStage1
    } else {
        ExecutionState::UnpackStage1
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let field_index = cb.query_cell(); //Fixme: query byte or u16 for different LIMB_BITS
        let step_curr = cb.curr.state.clone();
        let is_zero_num_field = IsZeroGadget::construct(cb, step_curr.aux0.expr());

        cb.require_equal(
            "opcode",
            step_curr.opcode.expr(),
            (Self::OPCODE as u64).expr(),
        );
        cb.require_equal(
            format!("{}, step_counter(0) == 1", Self::NAME),
            step_curr.step_counter.expr(),
            1u64.expr(),
        );
        cb.require_equal(
            format!("{},  stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_equal(
            format!(
                "{},  stack_pop_value(0).as_header().len() == aux0(0)",
                Self::NAME
            ),
            step_curr.stack_pop_value.as_header().len(),
            step_curr.aux0.expr(),
        );
        cb.require_no_stack_push();
        cb.require_no_local_op();

        cb.require_state_transition(vec![
            (FRAME_INDEX, Transition::Same),
            (MODULE_INDEX, Transition::Same),
            (FUNCTION_INDEX, Transition::Same),
        ]);
        let field_index_next = cb.cell_at_offset(&field_index, 1);
        if !VEC_UNPACK {
            cb.require_next_state(ExecutionState::UnpackStage2);
            cb.require_state_transition(vec![(PC, Transition::Same), (SP, Transition::Same)]);
            cb.require_equal(
                format!("{},  field_index(1) == aux0(0)", Self::NAME),
                field_index_next.expr(),
                step_curr.aux0.expr(),
            );
        }
        if VEC_UNPACK {
            cb.condition(not::expr(is_zero_num_field.expr()), |cb| {
                cb.require_next_state(ExecutionState::UnpackStage2);
                cb.require_state_transition(vec![(PC, Transition::Same), (SP, Transition::Same)]);
                cb.require_equal(
                    format!("{},  field_index(1) == aux0(0)", Self::NAME),
                    field_index_next.expr(),
                    step_curr.aux0.expr(),
                );
            });
            cb.condition(is_zero_num_field.expr(), |cb| {
                cb.require_state_transition(vec![
                    (PC, Transition::Delta((1).expr())),
                    (SP, Transition::Delta((-1).expr())),
                ]);
            });
        }

        UnpackStage1 {
            field_index,
            is_zero_num_field,
        }
    }

    fn assign(
        &self,
        step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();

        debug_assert_eq!(step_state.memory_ops.len(), 1);

        self.field_index.assign(region, offset, Value::unknown())?;
        let aux_value = region.get_advice(offset, step.aux0.get_column_idx(), Rotation::cur());
        self.is_zero_num_field.assign(region, offset, aux_value)?;

        Ok(step_state.memory_ops.len())
    }
}

#[derive(Clone, Debug)]
pub struct UnpackStage2<F, const VEC_UNPACK: bool> {
    field_index: Cell<F>,
    is_last_field: IsZeroGadget<F>,
    membership_gadget: MembershipGadget<F, 8>,
}
impl<F: Field, const VEC_UNPACK: bool> InstructionGadgetV2<F> for UnpackStage2<F, VEC_UNPACK> {
    const NAME: &'static str = if VEC_UNPACK {
        "VecUnpackStage2"
    } else {
        "UnpackStage2"
    };
    const OPCODE: Opcode = if VEC_UNPACK {
        Opcode::VecUnpack
    } else {
        Opcode::Unpack
    };
    const EXECUTION_STATE: ExecutionState = if VEC_UNPACK {
        ExecutionState::VecUnpackStage2
    } else {
        ExecutionState::UnpackStage2
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let field_index = cb.query_cell();
        let is_last_field = IsZeroGadget::construct(cb, field_index.expr() - 1u64.expr());
        let membership_gadget = MembershipGadget::<_, 8>::construct(cb);
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_prev_states(vec![
                ExecutionState::UnpackStage1,
                ExecutionState::UnpackStage2,
            ]);
            cb.require_equal(
                format!("{}, stack_pop_sub_index(0) == field_index(0)", Self::NAME),
                step_curr.stack_pop_sub_index.expr(),
                field_index.expr(),
            );
            cb.condition(step_curr.stack_pop_value_header.expr(), |cb| {
                cb.require_equal(
                    format!(
                        "{}, step_counter(0) == stack_pop_value(0).as_header().flen",
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
        });

        cb.not_first_row(|cb| {
            // we can only pop the member of [field_index,0,0,0]
            membership_gadget.configure(
                cb,
                field_index.expr(),
                step_curr.stack_pop_sub_index.expr(),
                Self::NAME,
            );
        });

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_equal(
            format!(
                "{}, stack_push_index(0) == sp(0) + field_index(0) - 1",
                Self::NAME
            ),
            step_curr.stack_push_index.expr(),
            step_curr.sp.expr() + field_index.expr() - 1u64.expr(),
        );
        cb.require_equal(
            format!("{}, stack_push_sub_index(0) * DEPTH_POW_OF_ONE_LEVEL + field_index(0) == stack_pop_sub_index(0)", Self::NAME),
            step_curr.stack_push_sub_index.expr() * DEPTH_POW_OF_ONE_LEVEL.expr() + field_index.expr(),
            step_curr.stack_pop_sub_index.expr(),
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

        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
            cb.require_cell_transition(field_index.clone(), Transition::Same);
        });
        cb.last_row(|cb| {
            cb.condition(not::expr(is_last_field.expr()), |cb| {
                cb.require_next_state(ExecutionState::UnpackStage2);
                cb.require_state_transition(vec![(PC, Transition::Same), (SP, Transition::Same)]);
                cb.require_cell_transition(field_index.clone(), Transition::Delta((-1).expr()));
            });
            cb.condition(is_last_field.expr(), |cb| {
                cb.require_state_transition(vec![
                    (PC, Transition::Delta(1.expr())),
                    (
                        SP,
                        Transition::To(step_curr.sp.expr() + step_curr.aux0.expr() - 1u64.expr()),
                    ),
                ]);
            });
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
            ]);
        });

        UnpackStage2 {
            field_index,
            is_last_field,
            membership_gadget,
        }
    }

    fn assign(
        &self,
        step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();
        let header_pop = step_state.memory_ops.first().unwrap().0.as_ref().unwrap();
        let field_index = header_pop.sub_index.first().cloned().unwrap() as u64;
        for (i, memory_op) in step_state.memory_ops.iter().enumerate() {
            let stack_pop = memory_op.0.as_ref().unwrap();
            self.field_index
                .assign(region, offset + i, Value::known(F::from(field_index)))?;
            self.is_last_field
                .assign(region, offset + i, F::from(field_index - 1))?;
            // TODO: unify the api of sub_index and header_index to membership gadget
            self.membership_gadget.assign(
                region,
                offset + i,
                field_index as u128,
                stack_pop.sub_index.into_u128(),
            )?;
        }
        Ok(step_state.memory_ops.len())
    }
}
