use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::call_stack::CallContext;
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::lookup_table::Lookup;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, AUX0, AUX1, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, OPCODE, PC, SP,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::{and, not};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{circuit::Value, plonk::Error};
use types::Field;

/// check the number of argument. If there is no arguments, enter entry function, else enter
/// the next stage
#[derive(Clone, Debug)]
pub struct StartStage1<F> {
    num_arg: Cell<F>,
    is_zero_num_arg: IsZeroGadget<F>,
}

impl<F: Field> InstructionGadgetV2<F> for StartStage1<F> {
    const NAME: &'static str = "StartStage1";
    const OPCODES: &'static [Opcode] = &[Opcode::Start];
    const EXECUTION_STATE: ExecutionState = ExecutionState::StartStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let num_arg = cb.query_cell();
        let is_zero_num_arg = IsZeroGadget::construct(cb, num_arg.expr());
        let step_curr = cb.curr.state.clone();

        cb.add_lookup(
            "entry function lookup",
            Lookup::Function {
                module_index: step_curr.module_index.expr(), // same as def_module_index
                function_handle_index: step_curr.aux0.expr(),
                def_module_index: step_curr.module_index.expr(),
                function_index: step_curr.function_index.expr(),
                num_arg: num_arg.expr(),
                entry: 1u64.expr(),
            },
        );

        cb.require_zero("frame_index = 0", step_curr.frame_index.expr());
        cb.require_equal(
            format!("{}, step_counter(0) == 1", Self::NAME),
            step_curr.step_counter.expr(),
            1u64.expr(),
        );

        cb.require_no_stack_pop();
        cb.require_no_stack_push();
        cb.require_no_local_op();

        cb.condition(is_zero_num_arg.expr(), |cb| {
            cb.require_state_transition(vec![(PC, Transition::To(0.expr()))]);
            cb.require_state_transition(vec![(SP, Transition::To(0.expr()))]);
        });
        cb.condition(not::expr(is_zero_num_arg.expr()), |cb| {
            cb.require_next_state(ExecutionState::StartStage2);
            cb.require_cell_transition(num_arg.clone(), Transition::Same);
            let local_index_next = cb.cell_at_offset(&step_curr.local_index, 1).expr();
            cb.require_equal(
                format!("{}, local_index(1) == num_arg(0) - 1", Self::NAME),
                local_index_next,
                num_arg.expr() - 1u64.expr(),
            );
        });

        cb.require_state_transition(
            [FRAME_INDEX, MODULE_INDEX, FUNCTION_INDEX]
                .into_iter()
                .map(|s| (s, Transition::Same))
                .collect(),
        );

        StartStage1 {
            num_arg,
            is_zero_num_arg,
        }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        let state = stage_state.step_states.first().unwrap();
        let num_arg = static_info
            .get_entry_function(
                state.step_state.module_index as usize,
                state.step_state.function_index as usize,
            )
            .unwrap_or_else(|| panic!("cannot find function"))
            .num_arg();

        self.num_arg
            .assign(region, offset, Value::known(F::from(num_arg as u64)))?;
        self.is_zero_num_arg
            .assign(region, offset, F::from(num_arg as u64))?;

        Ok(1)
    }
}

/// Store an argument into locals. Next stage will still be StartStage2, unless we process all the arguments.
#[derive(Clone, Debug)]
pub struct StartStage2<F> {
    num_arg: Cell<F>,
    is_zero_local_index: IsZeroGadget<F>,
}
impl<F: Field> InstructionGadgetV2<F> for StartStage2<F> {
    const NAME: &'static str = "StartStage2";
    const OPCODES: &'static [Opcode] = &[Opcode::Start];
    const EXECUTION_STATE: ExecutionState = ExecutionState::StartStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let num_arg = cb.query_cell();
        let is_zero_local_index = IsZeroGadget::construct(cb, cb.curr.state.local_index.expr());
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_prev_states(vec![
                ExecutionState::StartStage1,
                ExecutionState::StartStage2,
            ]);

            // local index is constrained in the StartStage1, only need constrain local_sub_index
            cb.require_zero(
                format!("{}, local_sub_index(0) == 0", Self::NAME),
                step_curr.local_sub_index.expr(),
            );

            //TODO: argument type check

            cb.condition(step_curr.local_write_value_header.expr(), |cb| {
                cb.require_equal(
                    "step_counter(0) == flen",
                    step_curr.step_counter.expr(),
                    step_curr.local_write_value.as_header().flen(),
                );
            });
            cb.condition(not::expr(step_curr.local_write_value_header.expr()), |cb| {
                cb.require_equal(
                    format!("{}, step_counter(0) == 1", Self::NAME),
                    step_curr.step_counter.expr(),
                    1u64.expr(),
                );
            });
        });

        cb.require_equal(
            format!("{}, local_frame_index(0) == frame_index(0)", Self::NAME),
            step_curr.local_frame_index.expr(),
            step_curr.frame_index.expr(),
        );
        cb.require_equal(
            format!("{}, local_read_value_invalid == 1", Self::NAME),
            step_curr.local_read_value_invalid.expr(),
            1u64.expr(),
        );
        cb.require_zero(
            format!("{}, local_write_value_invalid == 0", Self::NAME),
            step_curr.local_write_value_invalid.expr(),
        );

        cb.require_no_stack_pop();
        cb.require_no_stack_push();

        cb.not_last_row(|cb| {
            cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
            cb.require_cell_transition(num_arg.clone(), Transition::Same);
        });
        cb.last_row(|cb| {
            cb.condition(is_zero_local_index.expr(), |cb| {
                //all args have been processed
                cb.require_state_transition(vec![(PC, Transition::To(0.expr()))]);
                cb.require_state_transition(vec![(SP, Transition::To(0.expr()))]);
            });
            cb.condition(not::expr(is_zero_local_index.expr()), |cb| {
                cb.require_next_state(ExecutionState::StartStage2);
                cb.require_cell_transition(step_curr.local_index, Transition::Delta((-1).expr()));
            });
            cb.require_state_transition(
                [FRAME_INDEX, MODULE_INDEX, FUNCTION_INDEX]
                    .into_iter()
                    .map(|s| (s, Transition::Same))
                    .collect(),
            );
        });

        StartStage2 {
            num_arg,
            is_zero_local_index,
        }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        let step_state = stage_state.step_states.first().unwrap();
        let rows = step_state.memory_ops.len();
        let num_arg = region.get_advice(offset, self.num_arg.get_column_idx(), Rotation::prev());

        for (i, memory_op) in step_state.memory_ops.iter().enumerate() {
            self.num_arg
                .assign(region, offset + i, Value::known(num_arg))?;
            let local_index = memory_op.2.as_ref().unwrap().index;
            self.is_zero_local_index
                .assign(region, offset + i, F::from(local_index as u64))?;
        }

        Ok(rows)
    }
}
