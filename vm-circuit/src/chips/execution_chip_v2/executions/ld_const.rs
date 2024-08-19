use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::lookup_table::Lookup;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use halo2_proofs::plonk::Error;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug, Default)]
pub struct LdConst<F>(PhantomData<F>);
impl<F: Field> InstructionGadgetV2<F> for LdConst<F> {
    const NAME: &'static str = "LdConst";

    const OPCODES: &'static [Opcode] = &[Opcode::LdConst];
    const EXECUTION_STATE: ExecutionState = ExecutionState::LdConst;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in OPCODES",
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.condition(step_curr.stack_push_value_header.expr(), |cb| {
                cb.require_equal(
                    "step_counter(0) == flen",
                    step_curr.step_counter.expr(),
                    step_curr.stack_push_value.as_header().flen(),
                );
            });
            cb.condition(
                1u64.expr() - step_curr.stack_push_value_header.expr(),
                |cb| {
                    cb.require_equal(
                        "step_counter(0) == 1",
                        step_curr.step_counter.expr(),
                        1u64.expr(),
                    );
                },
            );
            cb.first_row(|cb| {
                cb.require_zero(
                    format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                    step_curr.stack_push_sub_index.expr(),
                );
            });
        });
        cb.add_lookup(
            "constant lookup",
            Lookup::Constant {
                module_index: step_curr.module_index.expr(),
                constant_index: step_curr.aux0.expr(),
                sub_index: step_curr.stack_push_sub_index.expr(),
                value: step_curr.stack_push_value.exprs(),
                header: step_curr.stack_push_value_header.expr(),
            },
        );
        cb.require_equal(
            format!("{}, stack_push_index(0) == sp(0) + 1", Self::NAME),
            step_curr.stack_push_index.expr(),
            step_curr.sp.expr() + 1u64.expr(),
        );
        cb.require_no_stack_pop();
        cb.require_no_local_op();

        cb.last_row(|cb| {
            cb.require_state_transition(
                [FRAME_INDEX, MODULE_INDEX, FUNCTION_INDEX]
                    .into_iter()
                    .map(|s| (s, Transition::Same))
                    .chain(vec![
                        (PC, Transition::Delta(1.expr())),
                        (SP, Transition::Delta(1.expr())),
                    ])
                    .collect(),
            );
        });
        Self::default()
    }

    fn assign(
        &self,
        _step: StepState<F>,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        // no need to assign anything else
        Ok(stage_state.rows())
    }
}
