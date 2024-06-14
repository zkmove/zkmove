use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::comparison::ComparisonGadget;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::value::NUM_OF_BYTES_U128;
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use types::Field;

#[derive(Clone, Debug)]
pub struct Le<F, const LE: bool> {
    comparison_hi: Option<ComparisonGadget<F, NUM_OF_BYTES_U128>>,
    comparison_lo: Option<ComparisonGadget<F, NUM_OF_BYTES_U128>>,
}
impl<F: Field, const LE: bool> InstructionGadgetV2<F> for Le<F, LE> {
    const NAME: &'static str = if LE { "Le" } else { "Gt" };
    const OPCODE: Opcode = if LE { Opcode::Le } else { Opcode::Gt };
    const EXECUTION_STATE: ExecutionState = if LE {
        ExecutionState::Le
    } else {
        ExecutionState::Gt
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let mut comparison_lo = None;
        let mut comparison_hi = None;

        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );
            cb.require_equal(
                "step_counter(0) == 2",
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
        });

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_value_header(0) == false", Self::NAME),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_no_local_op();

        cb.last_row(|cb| {
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );

            let lhs = step_curr.stack_pop_value.as_integer();
            let rhs = step_prev.stack_pop_value.as_integer();
            let comp_hi =
                ComparisonGadget::<_, NUM_OF_BYTES_U128>::construct(cb, lhs.hi(), rhs.hi());
            let comp_lo =
                ComparisonGadget::<_, NUM_OF_BYTES_U128>::construct(cb, lhs.lo(), rhs.lo());

            let (hi_lt, hi_eq) = comp_hi.expr();
            let (lo_lt, lo_eq) = comp_lo.expr();
            let le = hi_lt + hi_eq * (lo_lt + lo_eq);
            cb.require_boolean("le == 0 | 1", le.clone());

            let out = step_curr.stack_push_value.as_integer();
            cb.require_zero(format!("{}, out.hi() == 0", Self::NAME), out.hi());
            if LE {
                cb.require_equal(
                    format!("{}, out.lo() == le", Self::NAME),
                    out.lo(),
                    le.clone(),
                );
            } else {
                cb.require_equal(
                    format!("{}, out.lo() + le == 1", Self::NAME),
                    out.lo() + le,
                    1u64.expr(),
                );
            };
            comparison_lo = Some(comp_lo);
            comparison_hi = Some(comp_hi);

            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                step_curr.stack_push_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        Le {
            comparison_lo,
            comparison_hi,
        }
    }
}
