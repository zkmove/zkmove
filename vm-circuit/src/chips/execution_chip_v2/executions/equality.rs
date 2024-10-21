use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::SubIndexReverse;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::lt::LtGadget;
use crate::chips::execution_chip_v2::step_v2::{StepState, PC, SP};
use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::{
    ConstraintBuilderV2, Transition,
};
use crate::chips::execution_chip_v2::utils::to_field::{ToField, ToFields};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utils::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use crate::utils::rlc;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::not;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2_proofs::poly::Rotation;
use types::Field;

#[derive(Clone, Debug)]
pub struct Equality<F, const STAGE1: bool, const EQ: bool> {
    rlc1: Cell<F>,
    rlc2: Cell<F>,
    // define stack_pop_sub_index_reverse to constrain sub_index monotonically increasing,
    // prevents malicious prover from faking eq as neq or vice versa.
    stack_pop_sub_index_reverse: Cell<F>,
    sub_index_reverse: SubIndexReverse<F, 8>,
    sub_index_lt: LtGadget<F, 16>,
    rlc1_rlc2_eq: IsZeroGadget<F>,
}
impl<F: Field, const STAGE1: bool, const EQ: bool> InstructionGadgetV2<F>
    for Equality<F, STAGE1, EQ>
{
    const NAME: &'static str = if EQ { "Eq" } else { "Neq" };
    const EXECUTION_STATE: ExecutionState = match (EQ, STAGE1) {
        (true, true) => ExecutionState::EqStage1,
        (true, false) => ExecutionState::EqStage2,
        (false, true) => ExecutionState::NeqStage1,
        (false, false) => ExecutionState::NeqStage2,
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let rlc1 = cb.query_cell();
        let rlc2 = cb.query_cell();
        let stack_pop_sub_index_reverse = cb.query_cell();
        let stack_pop_sub_index_reverse_prev = cb.cell_at_offset(&stack_pop_sub_index_reverse, -1);
        let sub_index_reverse =
            SubIndexReverse::construct(cb, step_curr.stack_pop_sub_index.expr(), Self::NAME);
        let sub_index_lt = LtGadget::construct(
            cb,
            stack_pop_sub_index_reverse_prev.expr(),
            stack_pop_sub_index_reverse.expr(),
        );
        let rlc1_rlc2_eq = IsZeroGadget::construct(cb, rlc1.expr() - rlc2.expr());

        let stack_pop_rlc = cb.rlc_with_randomness(
            &[
                step_curr.stack_pop_sub_index.expr(),
                step_curr.stack_pop_value_header.expr(),
            ]
            .into_iter()
            .chain(step_curr.stack_pop_value.exprs())
            .collect::<Vec<_>>(),
            cb.row_randomness(),
        );

        cb.first_row(|cb| {
            if !STAGE1 {
                cb.require_prev_state(if EQ {
                    ExecutionState::EqStage1
                } else {
                    ExecutionState::NeqStage1
                });
            }

            cb.require_in_set(
                "opcode in OPCODES",
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                step_curr.stack_pop_sub_index.expr(),
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

            cb.require_zero(
                format!("{}, stack_pop_sub_index_reverse(0) == 0", Self::NAME),
                stack_pop_sub_index_reverse.expr(),
            );

            if STAGE1 {
                cb.require_equal(
                    format!("{}, rlc1(0) == stack_pop_rlc", Self::NAME),
                    rlc1.expr(),
                    stack_pop_rlc.clone(),
                );
            } else {
                cb.require_equal(
                    format!("{}, rlc2(0) == stack_pop_rlc", Self::NAME),
                    rlc2.expr(),
                    stack_pop_rlc.clone(),
                );
            }
        });

        cb.not_first_row(|cb| {
            cb.require_equal(
                format!("{}, stack_pop_sub_index_reverse(0) == SubIndexReverse::expr(stack_pop_sub_index(0))", Self::NAME),
                stack_pop_sub_index_reverse.expr(),
                sub_index_reverse.expr(),
            );
            cb.require_true(
                format!("{}, stack_pop_sub_index_reverse(-1) < stack_pop_sub_index_reverse(0)", Self::NAME),
                sub_index_lt.expr(),
            );
            let column_randomness = cb.column_randomness();
            if STAGE1 {
                let rlc1_prev = cb.cell_at_offset(&rlc1, -1).expr();
                let rlc1_curr = cb.rlc_with_randomness(&[stack_pop_rlc.clone(), rlc1_prev], column_randomness.clone());
                cb.require_equal(
                    format!("{}, rlc1(0) == gamma^4 * rlc1(-1) + stack_pop_rlc", Self::NAME),
                    rlc1.expr(),
                    rlc1_curr,
                );
            } else {
                let rlc2_prev = cb.cell_at_offset(&rlc2, -1).expr();
                let rlc2_curr = cb.rlc_with_randomness(&[stack_pop_rlc.clone(), rlc2_prev], column_randomness);
                cb.require_equal(
                    format!("{}, rlc2(0) == gamma^4 * rlc2(-1) + stack_pop_rlc", Self::NAME),
                    rlc2.expr(),
                    rlc2_curr,
                );
            }
        });

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_no_local_op();
        if !STAGE1 {
            let rlc1_prev = cb.cell_at_offset(&rlc1, -1).expr();
            cb.require_equal(
                format!("{}, rlc1(0) == rlc1(-1)", Self::NAME),
                rlc1.expr(),
                rlc1_prev,
            );
        }

        cb.not_last_row(|cb| {
            cb.require_no_stack_push();
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

        cb.last_row(|cb| {
            if STAGE1 {
                cb.require_no_stack_push();
                cb.require_state_transition(vec![
                    (SP, Transition::Delta((-1).expr())),
                    (PC, Transition::Same),
                ]);
                cb.require_next_state(if EQ {
                    ExecutionState::EqStage2
                } else {
                    ExecutionState::NeqStage2
                });
            } else {
                cb.require_equal(
                    format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
                    cb.curr.state.stack_push_index.expr(),
                    cb.curr.state.sp.expr(),
                );
                cb.require_zero(
                    format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                    cb.curr.state.stack_push_sub_index.expr(),
                );
                cb.require_boolean(
                    format!("{}, stack_push_value(0) == true | false", Self::NAME),
                    cb.curr.state.stack_push_value.expr(),
                );
                cb.require_zero(
                    format!("{}, stack_push_value_header(0) == false", Self::NAME),
                    cb.curr.state.stack_push_value_header.expr(),
                );
                cb.require_equal(
                    "stack_push_version(0) == clk(0)",
                    cb.curr.state.stack_push_version.expr(),
                    cb.curr.state.clk.expr(),
                );

                if EQ {
                    cb.condition(cb.curr.state.stack_push_value.expr(), |cb| {
                        cb.require_equal(
                            format!("{}, rlc1(0) == rlc2(0)", Self::NAME),
                            rlc1.expr(),
                            rlc2.expr(),
                        );
                    });
                    cb.condition(not::expr(cb.curr.state.stack_push_value.expr()), |cb| {
                        cb.require_zero(
                            format!("{}, rlc1(0) != rlc2(0)", Self::NAME),
                            rlc1_rlc2_eq.expr(),
                        );
                    });
                } else {
                    cb.condition(cb.curr.state.stack_push_value.expr(), |cb| {
                        cb.require_zero(
                            format!("{}, rlc1(0) != rlc2(0)", Self::NAME),
                            rlc1_rlc2_eq.expr(),
                        );
                    });
                    cb.condition(not::expr(cb.curr.state.stack_push_value.expr()), |cb| {
                        cb.require_equal(
                            format!("{}, rlc1(0) == rlc2(0)", Self::NAME),
                            rlc1.expr(),
                            rlc2.expr(),
                        );
                    });
                }

                cb.require_state_transition(vec![
                    (SP, Transition::Same),
                    (PC, Transition::Delta(1.expr())),
                ]);
            }
        });

        Equality {
            rlc1,
            rlc2,
            stack_pop_sub_index_reverse,
            sub_index_reverse,
            sub_index_lt,
            rlc1_rlc2_eq,
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
        let mut stack_pop_sub_index_reverse_prev = F::zero();
        let mut prev_rlc = F::zero();
        for (i, op) in step_state.memory_ops.iter().enumerate() {
            let current_offset = offset + i;
            let stack_pop = op.0.as_ref().unwrap();
            let sub_index = op.0.as_ref().unwrap().sub_index.clone();
            self.sub_index_reverse
                .assign(region, current_offset, &sub_index)?;
            let sub_index_value: F = sub_index.to_field();
            let v_reverse = if sub_index_value.is_zero().into() {
                F::zero()
            } else {
                F::invert(&sub_index_value).unwrap()
            };
            self.stack_pop_sub_index_reverse.assign(
                region,
                current_offset,
                Value::known(v_reverse),
            )?;
            self.sub_index_lt.assign(
                region,
                current_offset,
                stack_pop_sub_index_reverse_prev,
                v_reverse,
            )?;

            stack_pop_sub_index_reverse_prev = v_reverse;
            let row_randomness = region.challenges().row_keccak_input();
            let column_randomness = region.challenges().column_keccak_input();
            let stack_pop_rlc = row_randomness.map(|randomness| {
                rlc::generic(
                    [
                        sub_index_value,
                        if stack_pop.value_header {
                            F::one()
                        } else {
                            F::zero()
                        },
                    ]
                    .into_iter()
                    .chain(stack_pop.value.to_fields()),
                    randomness,
                )
            });
            let current_rlc_value =
                stack_pop_rlc
                    .zip(column_randomness)
                    .map(|(stack_pop_rlc, randomness)| {
                        prev_rlc = rlc::generic([stack_pop_rlc, prev_rlc], randomness);
                        prev_rlc
                    });

            let (rlc1_value, rlc2_value) = if STAGE1 {
                (current_rlc_value, Value::known(F::zero()))
            } else {
                let rlc1_prev = region.get_advice(
                    current_offset,
                    self.rlc1.get_column_idx(),
                    Rotation(self.rlc1.get_rotation() as i32 - 1), // get prev rlc1
                );
                (Value::known(rlc1_prev), current_rlc_value)
            };
            self.rlc1.assign(region, current_offset, rlc1_value)?;
            self.rlc2.assign(region, current_offset, rlc2_value)?;
            rlc1_value
                .zip(rlc2_value)
                .map(|(v1, v2)| v1 - v2)
                .error_if_known_and(|v| {
                    self.rlc1_rlc2_eq
                        .assign(region, current_offset, *v)
                        .is_err()
                })?;
        }
        Ok(step_state.memory_ops.len())
    }
}
