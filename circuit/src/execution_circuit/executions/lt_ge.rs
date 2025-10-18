use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::instance::InstanceTable;
use crate::execution_circuit::math_gadgets::comparison::ComparisonGadget;
use crate::execution_circuit::math_gadgets::lt::LtGadget;
use crate::execution_circuit::step::{StepState, PC, SP};
use crate::execution_circuit::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::execution_circuit::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::execution_circuit::value::NUM_OF_BYTES_U128;
use crate::execution_circuit::InstructionGadgetV2;
use crate::utils::cached_region::CachedRegion;
use gadgets::util::Expr;
use halo2_proofs::plonk::ErrorFront as Error;
use types::Field;
use witnesses::static_info::StaticInfo;
use witnesses::step_state::StageState;

#[derive(Clone, Debug)]
pub struct Lt<F, const LT: bool> {
    lt_lo: LtGadget<F, NUM_OF_BYTES_U128>,
    comparison_hi: ComparisonGadget<F, NUM_OF_BYTES_U128>,
}
impl<F: Field, const LT: bool> InstructionGadgetV2<F> for Lt<F, LT> {
    const NAME: &'static str = if LT { "Lt" } else { "Ge" };
    const EXECUTION_STATE: ExecutionState = if LT {
        ExecutionState::Lt
    } else {
        ExecutionState::Ge
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let mut lt_lo = None;
        let mut comparison_hi = None;

        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in OPCODES",
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.require_equal(
                "step_counter(0) == 2",
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr(),
            );
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

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
                format!("{}, stack_pop_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );

            let lhs = step_curr.stack_pop_value.as_integer();
            let rhs = step_prev.stack_pop_value.as_integer();
            let comparison_gadget_hi =
                ComparisonGadget::<_, NUM_OF_BYTES_U128>::construct(cb, lhs.hi(), rhs.hi());
            let lt_gadget_lo = LtGadget::<_, NUM_OF_BYTES_U128>::construct(cb, lhs.lo(), rhs.lo());

            let (hi_lt, hi_eq) = comparison_gadget_hi.expr();
            let lt = hi_lt + hi_eq * lt_gadget_lo.expr();
            cb.require_boolean("lt == 0 | 1", lt.clone());

            let out = step_curr.stack_push_value.as_integer();
            cb.require_zero(format!("{}, out.hi() == 0", Self::NAME), out.hi());
            if LT {
                cb.require_equal(
                    format!("{}, out.lo() == lt", Self::NAME),
                    out.lo(),
                    lt.clone(),
                );
            } else {
                cb.require_equal(
                    format!("{}, out.lo() + lt == 1", Self::NAME),
                    out.lo() + lt,
                    1u64.expr(),
                );
            };
            lt_lo = Some(lt_gadget_lo);
            comparison_hi = Some(comparison_gadget_hi);

            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                step_curr.stack_push_value_header.expr(),
            );
            cb.require_equal(
                "stack_push_version(0) == clk(0)",
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            cb.require_state_transition(vec![
                (SP, Transition::Delta((-1).expr())),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        Lt {
            lt_lo: lt_lo.unwrap(),
            comparison_hi: comparison_hi.unwrap(),
        }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();
        let rhs = step_state.memory_ops[0].0.clone().unwrap().value;
        let lhs = step_state.memory_ops[1].0.clone().unwrap().value;
        let rhs_lo = rhs.lo();
        let rhs_hi = rhs.hi();
        let lhs_lo = lhs.lo();
        let lhs_hi = lhs.hi();

        debug_assert_eq!(step_state.memory_ops.len(), 2);
        self.lt_lo.assign(
            region,
            offset + 1,
            F::from_u128(lhs_lo),
            F::from_u128(rhs_lo),
        )?;
        self.comparison_hi.assign(
            region,
            offset + 1,
            F::from_u128(lhs_hi),
            F::from_u128(rhs_hi),
        )?;

        Ok(step_state.memory_ops.len())
    }
}
