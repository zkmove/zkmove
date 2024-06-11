use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::SubIndexReverse;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::lt::LtGadget;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use gadgets::util::not;
use types::Field;

#[derive(Clone, Debug)]
pub struct Equality<F: Field, const STAGE1: bool, const EQ: bool> {
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
    const OPCODE: Opcode = if EQ { Opcode::Eq } else { Opcode::Neq };
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
        let sub_index_reverse = SubIndexReverse::<_, 8>::construct(
            cb,
            step_curr.stack_pop_sub_index.expr(),
            Self::NAME,
        );
        let sub_index_lt = LtGadget::construct(
            cb,
            stack_pop_sub_index_reverse_prev.expr(),
            stack_pop_sub_index_reverse.expr(),
        );
        let rlc1_rlc2_eq = IsZeroGadget::construct(cb, rlc1.expr() - rlc2.expr());
        let stack_pop_rlc = cb.rlc(&[
            step_curr.stack_pop_sub_index.expr(),
            step_curr.stack_pop_value_header.expr(),
            step_curr.stack_pop_value.expr(), //stack_pop_value must be the last element of the array
        ]);

        cb.first_row(|cb| {
            if !STAGE1 {
                cb.require_prev_state(if EQ {
                    ExecutionState::EqStage1
                } else {
                    ExecutionState::NeqStage1
                });
            }

            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
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
            //in order not to conflict with inner rlc, we use gamma^4 as randomness
            let randomness = cb.randomness().square().square();
            if STAGE1 {
                let rlc1_prev = cb.cell_at_offset(&rlc1, -1).expr();
                let rlc1_curr = cb.rlc_with_randomness(&[stack_pop_rlc.clone(), rlc1_prev], randomness.clone());
                cb.require_equal(
                    format!("{}, rlc1(0) == gamma^4 * rlc1(-1) + stack_pop_rlc", Self::NAME),
                    rlc1.expr(),
                    rlc1_curr,
                );
            } else {
                let rlc2_prev = cb.cell_at_offset(&rlc2, -1).expr();
                let rlc2_curr = cb.rlc_with_randomness(&[stack_pop_rlc.clone(), rlc2_prev], randomness);
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
                cb.require_state_transition(vec![
                    (FRAME_INDEX, Transition::Same),
                    (MODULE_INDEX, Transition::Same),
                    (FUNCTION_INDEX, Transition::Same),
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
                    format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
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
                    (FRAME_INDEX, Transition::Same),
                    (MODULE_INDEX, Transition::Same),
                    (FUNCTION_INDEX, Transition::Same),
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
}
