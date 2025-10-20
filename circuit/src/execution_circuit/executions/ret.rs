use crate::execution_circuit::call_stack::CallContext;
use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::step::{StepState, FRAME_INDEX, SP};
use crate::execution_circuit::InstructionGadgetV2;
use crate::gadgets::is_zero::IsZeroGadget;
use crate::gadgets::range_check::RangeCheckGadget;
use crate::public_inputs::InstanceTable;
use crate::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use crate::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use gadgets::util::not;
use gadgets::util::Expr;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{ErrorFront as Error, Expression};
use halo2_proofs::poly::Rotation;
use types::Field;
use witnesses::static_info::StaticInfo;
use witnesses::step_state::{StageExtraAssignData, StageState};

#[derive(Clone, Debug)]
pub struct Ret<F> {
    pub call_context: CallContext<Expression<F>>,
    is_zero_frame_index: IsZeroGadget<F>,
    call_context_version: Cell<F>,
    call_context_version_range_check: RangeCheckGadget<F, 4>,
}

impl<F: Field> InstructionGadgetV2<F> for Ret<F> {
    const NAME: &'static str = "Ret";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Ret;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let is_zero_frame_index = IsZeroGadget::construct(cb, step_curr.frame_index.expr());
        let call_context_version = cb.query_cell();
        let mut call_context_version_range_check = None;

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
            cb.require_next_states(vec![ExecutionState::Teardown, ExecutionState::Stop]);
        });
        let frame_index_next = cb.cell_at_offset(&step_curr.frame_index, 1).expr();
        let module_index_next = cb.cell_at_offset(&step_curr.module_index, 1).expr();
        let function_index_next = cb.cell_at_offset(&step_curr.function_index, 1).expr();
        let pc_next = cb.cell_at_offset(&step_curr.pc, 1).expr();

        let [index, caller_module_index, caller_function_index, caller_pc, version] = [
            frame_index_next,
            module_index_next,
            function_index_next,
            pc_next - 1.expr(),
            call_context_version.expr(),
        ]
        .map(|e| not::expr(is_zero_frame_index.expr()) * e);

        let call_context = CallContext {
            index,
            caller_module_index,
            caller_function_index,
            caller_pc,
            version,
        };

        cb.condition(not::expr(is_zero_frame_index.expr()), |cb| {
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Delta((-1).expr())),
                (SP, Transition::Same),
            ]);
            // call_context_version < clk(0)
            let call_context_version_range_check_ = RangeCheckGadget::construct(
                cb,
                cb.curr.state.clk.expr() - call_context_version.expr(),
            );
            call_context_version_range_check = Some(call_context_version_range_check_);
        });

        Ret {
            call_context,
            is_zero_frame_index,
            call_context_version,
            call_context_version_range_check: call_context_version_range_check.unwrap(),
        }
    }

    fn assign(
        &self,
        step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        let extra_data = match stage_state.extra_data.as_ref() {
            Some(StageExtraAssignData::Ret(extra_data)) => extra_data,
            _ => unreachable!(),
        };
        match &extra_data.caller {
            Some(caller) => {
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
                let clk = region.get_advice(offset, step.clk.get_column_idx(), Rotation::cur());
                self.call_context_version_range_check.assign(
                    region,
                    offset,
                    clk - F::from(extra_data.frame_version),
                )?;
            }
            None => {
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
