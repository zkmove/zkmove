use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::call_stack::CallContext;
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::step_v2::{StepState, FRAME_INDEX, SP};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::{StageExtraAssignData, StageState};
use gadgets::util::not;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use types::Field;

#[derive(Clone, Debug)]
pub struct Ret<F> {
    pub call_context: CallContext<F>,
    is_zero_frame_index: IsZeroGadget<F>,
    call_context_version: Cell<F>,
}

impl<F: Field> InstructionGadgetV2<F> for Ret<F> {
    const NAME: &'static str = "Ret";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Ret;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let call_context = CallContext::construct(cb);
        let is_zero_frame_index = IsZeroGadget::construct(cb, step_curr.frame_index.expr());
        let call_context_version = cb.query_cell();

        cb.require_in_set(
            "opcode in OPCODES",
            step_curr.opcode.expr(),
            Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
        );
        cb.require_equal(
            format!("{}, step_counter(0) == 1", Self::NAME),
            step_curr.step_counter.expr(),
            1u64.expr(),
        );

        cb.require_no_stack_pop();
        cb.require_no_stack_push();
        cb.require_no_local_op();

        cb.condition(is_zero_frame_index.expr(), |cb| {
            call_context.require_zero(cb);
            //TODO: state transition, STOP or go to NOP when necessary
        });
        cb.condition(not::expr(is_zero_frame_index.expr()), |cb| {
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Delta((-1).expr())),
                (SP, Transition::Same),
            ]);
            let frame_index_next = cb.cell_at_offset(&step_curr.frame_index, 1).expr();
            let module_index_next = cb.cell_at_offset(&step_curr.module_index, 1).expr();
            let function_index_next = cb.cell_at_offset(&step_curr.function_index, 1).expr();
            let pc_next = cb.cell_at_offset(&step_curr.pc, 1).expr();
            call_context.configure(
                cb,
                frame_index_next,
                module_index_next,
                function_index_next,
                pc_next - 1u64.expr(),
                call_context_version.expr(),
            );
            // TODO: call_context_version < clk(0)
        });

        Ret {
            call_context,
            is_zero_frame_index,
            call_context_version,
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
        let extra_data = match stage_state.extra_data.as_ref() {
            Some(StageExtraAssignData::Ret(extra_data)) => extra_data,
            _ => unreachable!(),
        };
        match &extra_data.caller {
            Some(caller) => {
                self.call_context.assign(
                    region,
                    offset,
                    F::from(caller.caller_frame_index as u64),
                    F::from(caller.caller_module_index),
                    F::from(caller.caller_function_index as u64),
                    F::from(caller.caller_pc),
                    F::from(extra_data.frame_version),
                )?;
                self.call_context_version.assign(
                    region,
                    offset,
                    Value::known(F::from(extra_data.frame_version)),
                )?;
                self.is_zero_frame_index.assign(
                    region,
                    offset,
                    F::from((caller.caller_frame_index + 1) as u64),
                )?;
            }
            None => {
                self.call_context.assign(
                    region,
                    offset,
                    F::zero(),
                    F::zero(),
                    F::zero(),
                    F::zero(),
                    F::from(extra_data.frame_version),
                )?;
                self.call_context_version.assign(
                    region,
                    offset,
                    Value::known(F::from(extra_data.frame_version)),
                )?;

                self.is_zero_frame_index.assign(region, offset, F::zero())?;
            }
        }
        Ok(1)
    }
}
