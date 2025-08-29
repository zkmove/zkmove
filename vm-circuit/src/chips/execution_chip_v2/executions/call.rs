use crate::chips::execution_chip_v2::call_stack::CallContext;
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::instance::InstanceTable;
use crate::chips::execution_chip_v2::lookup_table::Lookup;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, AUX0, AUX1, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, OPCODE, PC, SP,
};
use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::{
    ConstraintBuilderV2, Transition,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::Expr;
use gadgets::util::{and, not};
use halo2_proofs::plonk::Expression;
use halo2_proofs::poly::Rotation;
use halo2_proofs::{circuit::Value, plonk::ErrorFront as Error};
use types::Field;

/// check the number of argument. If the function has no arguments, enter callee, else enter stage2
#[derive(Clone, Debug)]
pub struct CallStage1<F> {
    num_arg: Cell<F>,
    pub call_context: CallContext<Expression<F>>,
    is_zero_num_arg: IsZeroGadget<F>,
}

impl<F: Field> InstructionGadgetV2<F> for CallStage1<F> {
    const NAME: &'static str = "CallStage1";
    const EXECUTION_STATE: ExecutionState = ExecutionState::CallStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let num_arg = cb.query_cell();
        let is_zero_num_arg = IsZeroGadget::construct(cb, num_arg.expr());
        let step_curr = cb.curr.state.clone();
        let step_next = cb.step_state_at_offset(1);

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
        cb.require_state_transition(vec![(SP, Transition::Same)]);
        let call_context = CallContext {
            index: step_curr.frame_index.expr(),
            caller_module_index: step_curr.module_index.expr(),
            caller_function_index: step_curr.function_index.expr(),
            caller_pc: step_curr.pc.expr(),
            version: step_curr.clk.expr(),
        };

        cb.condition(is_zero_num_arg.expr(), |cb| {
            cb.add_lookup(
                "function lookup",
                Lookup::Function {
                    module_index: step_curr.module_index.expr(),
                    function_handle_index: step_curr.aux0.expr(),
                    def_module_index: step_next.module_index.expr(),
                    function_index: step_next.function_index.expr(),
                    num_arg: num_arg.expr(),
                    entry: 0u64.expr(),
                },
            );
            cb.require_state_transition(vec![
                (PC, Transition::To(0u64.expr())),
                (FRAME_INDEX, Transition::Delta(1.expr())),
            ]);
        });
        cb.condition(not::expr(is_zero_num_arg.expr()), |cb| {
            cb.require_next_state(ExecutionState::CallStage2);
            cb.require_cell_transition(num_arg.clone(), Transition::Same);
            let local_index_next = cb.cell_at_offset(&step_curr.local_index, 1).expr();
            cb.require_equal(
                format!("{}, local_index(1) == num_arg(0) - 1", Self::NAME),
                local_index_next,
                num_arg.expr() - 1u64.expr(),
            );
            cb.require_state_transition(
                [
                    FRAME_INDEX,
                    MODULE_INDEX,
                    FUNCTION_INDEX,
                    PC,
                    OPCODE,
                    AUX0,
                    AUX1,
                ]
                .into_iter()
                .map(|s| (s, Transition::Same))
                .collect(),
            );
        });

        CallStage1 {
            num_arg,
            call_context,
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
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        let state = stage_state.step_states.first().unwrap();
        let num_arg = static_info
            .get_function(state.step_state.module_index, state.step_state.aux0 as u16)
            .unwrap_or_else(|| panic!("cannot find function"))
            .num_arg;
        self.num_arg
            .assign(region, offset, Value::known(F::from(num_arg as u64)))?;

        self.is_zero_num_arg
            .assign(region, offset, F::from(num_arg as u64))?;

        Ok(1)
    }
}

/// invalidate old value in the local_index corresponding to an argument.
/// the next stage must be stage3. we need to enter this stage 'num_arg' times.
#[derive(Clone, Debug)]
pub struct CallStage2<F> {
    num_arg: Cell<F>,
}

impl<F: Field> InstructionGadgetV2<F> for CallStage2<F> {
    const NAME: &'static str = "CallStage2";
    const EXECUTION_STATE: ExecutionState = ExecutionState::CallStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let num_arg = cb.query_cell();
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_prev_states(vec![ExecutionState::CallStage1, ExecutionState::CallStage3]);
            cb.require_zero(
                format!("{}, local_sub_index(0) == 0", Self::NAME),
                step_curr.local_sub_index.expr(),
            );
            let valid_complex_value = and::expr([
                not::expr(step_curr.local_read_value_invalid.expr()),
                step_curr.stack_pop_value_header.expr(),
            ]);
            cb.condition(valid_complex_value.clone(), |cb| {
                cb.require_equal(
                    "step_counter(0) == flen",
                    step_curr.step_counter.expr(),
                    step_curr.stack_pop_value.as_header().flen(),
                );
            });
            cb.condition(not::expr(valid_complex_value), |cb| {
                cb.require_equal(
                    format!("{}, step_counter(0) == 1", Self::NAME),
                    step_curr.step_counter.expr(),
                    1u64.expr(),
                );
            });
        });

        cb.require_no_stack_pop();
        cb.require_no_stack_push();

        cb.require_equal(
            format!("{}, local_frame_index(0) == frame_index(0) + 1", Self::NAME),
            step_curr.local_frame_index.expr(),
            step_curr.frame_index.expr() + 1u64.expr(), //write to local of next frame
        );
        cb.require_true(
            format!("{}, local_write_value_invalid == 1", Self::NAME),
            step_curr.local_write_value_invalid.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value(0) == local_read_value(0)",
                Self::NAME
            ),
            step_curr.local_write_value.expr(),
            step_curr.local_read_value.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value_header(0) == local_read_value_header(0)",
                Self::NAME
            ),
            step_curr.local_write_value_header.expr(),
            step_curr.local_read_value_header.expr(),
        );
        cb.require_equal(
            "local_write_version(0) == clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );

        cb.require_state_transition(vec![(SP, Transition::Same)]);
        cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
        cb.require_cell_transition(num_arg.clone(), Transition::Same);

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::CallStage3);
            cb.require_state_transition(
                [PC, OPCODE, AUX0, AUX1]
                    .into_iter()
                    .map(|s| (s, Transition::Same))
                    .collect(),
            );
        });

        CallStage2 { num_arg }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        let rows = stage_state.rows();
        let num_arg = region.get_advice(offset, self.num_arg.get_column_idx(), Rotation::prev());
        for i in 0..rows {
            self.num_arg
                .assign(region, offset + i, Value::known(num_arg))?;
        }

        Ok(rows)
    }
}

/// pop an argument and store into local of the next frame.
/// the previous stage must be stage2. The next stage is still stage2, unless we have
/// processed all the arguments. We need to enter this stage 'num_arg' times.
#[derive(Clone, Debug)]
pub struct CallStage3<F> {
    num_arg: Cell<F>,
    is_zero_local_index: IsZeroGadget<F>,
}
impl<F: Field> InstructionGadgetV2<F> for CallStage3<F> {
    const NAME: &'static str = "CallStage3";
    const EXECUTION_STATE: ExecutionState = ExecutionState::CallStage3;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let num_arg = cb.query_cell();
        let is_zero_local_index = IsZeroGadget::construct(cb, cb.curr.state.local_index.expr());
        let step_curr = cb.curr.state.clone();
        let step_next = cb.step_state_at_offset(1);

        cb.first_row(|cb| {
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                step_curr.stack_pop_sub_index.expr(),
            );
            cb.condition(step_curr.stack_pop_value_header.expr(), |cb| {
                cb.require_equal(
                    "step_counter(0) == flen",
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

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_equal(
            format!("{}, local_frame_index(0) == frame_index(0) + 1", Self::NAME),
            step_curr.local_frame_index.expr(),
            step_curr.frame_index.expr() + 1u64.expr(), //write to local of next frame
        );
        cb.require_equal(
            format!(
                "{}, local_sub_index(0) == stack_pop_sub_index(0)",
                Self::NAME
            ),
            step_curr.local_sub_index.expr(),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_equal(
            format!("{}, local_read_value_invalid == 1", Self::NAME),
            step_curr.local_read_value_invalid.expr(),
            1u64.expr(),
        );
        cb.require_equal(
            format!("{}, local_write_value(0) == stack_pop_value(0)", Self::NAME),
            step_curr.local_write_value.expr(),
            step_curr.stack_pop_value.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value_header(0) == stack_pop_value_header(0)",
                Self::NAME
            ),
            step_curr.local_write_value_header.expr(),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_zero(
            format!("{}, local_write_value_invalid == 0", Self::NAME),
            step_curr.local_write_value_invalid.expr(),
        );
        cb.require_equal(
            "local_write_version(0) == clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_no_stack_push();

        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
            cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
            cb.require_cell_transition(num_arg.clone(), Transition::Same);
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
            cb.condition(is_zero_local_index.expr(), |cb| {
                //all args have been processed
                cb.add_lookup(
                    "function lookup",
                    Lookup::Function {
                        module_index: step_curr.module_index.expr(),
                        function_handle_index: step_curr.aux0.expr(),
                        def_module_index: step_next.module_index.expr(),
                        function_index: step_next.function_index.expr(),
                        num_arg: num_arg.expr(),
                        entry: 0u64.expr(),
                    },
                );
                cb.require_state_transition(vec![
                    (FRAME_INDEX, Transition::Delta(1.expr())),
                    (PC, Transition::To(0.expr())),
                ]);
            });
            cb.condition(not::expr(is_zero_local_index.expr()), |cb| {
                cb.require_next_state(ExecutionState::CallStage2);
                cb.require_cell_transition(step_curr.local_index, Transition::Delta((-1).expr()));
                cb.require_state_transition(
                    [
                        FRAME_INDEX,
                        MODULE_INDEX,
                        FUNCTION_INDEX,
                        PC,
                        OPCODE,
                        AUX0,
                        AUX1,
                    ]
                    .into_iter()
                    .map(|s| (s, Transition::Same))
                    .collect(),
                );
            });
        });

        CallStage3 {
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
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
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
