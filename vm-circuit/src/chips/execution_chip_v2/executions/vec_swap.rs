use crate::chips::execution_chip_v2::executions::{
    ExecutionState, ExtendedSubIndex, DEPTH_POW_OF_ONE_LEVEL,
};
use crate::chips::execution_chip_v2::step_v2::{StepState, AUX0, AUX1, OPCODE, PC, SP};
use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::{
    ConstraintBuilderV2, Transition,
};
use crate::chips::execution_chip_v2::utils::to_field::ToFields;
use crate::chips::execution_chip_v2::value::Index;
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::not;
use gadgets::util::Expr;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2_proofs::poly::Rotation;
use std::iter::once;
use types::Field;

#[derive(Clone)]
pub struct VecSwapStage_1<F> {
    index1: Cell<F>,
    index2: Cell<F>,
    ref_local_sub_index: Cell<F>,
}

impl<F: Field> VecSwapStage_1<F> {
    const STEP_ROWS: u64 = 3;
}
impl<F: Field> InstructionGadgetV2<F> for VecSwapStage_1<F> {
    const NAME: &'static str = "VecSwap_Stage1";
    const EXECUTION_STATE: ExecutionState = ExecutionState::VecSwapStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let index1 = cb.query_cell();
        let index2 = cb.query_cell();
        let ref_local_sub_index = cb.query_cell();

        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in OPCODES",
                cb.curr.state.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.require_equal(
                "step_counter(0)==3",
                cb.curr.state.step_counter.expr(),
                Self::STEP_ROWS.expr(),
            );
        });

        cb.require_equal(
            "stack_pop_index(0) == sp(0)",
            cb.curr.state.stack_pop_index.expr(),
            cb.curr.state.sp.expr(),
        );
        cb.require_zero(
            "stack_pop_sub_index(0) == 0",
            cb.curr.state.stack_pop_sub_index.expr(),
        );

        cb.require_zero(
            "stack_pop_value_header(0) == false",
            cb.curr.state.stack_pop_value_header.expr(),
        );
        cb.require_no_stack_push();
        cb.require_no_local_op();
        let step_prev = cb.step_state_at_offset(-1);
        let step_penult = cb.step_state_at_offset(-2);
        cb.last_row(|cb| {
            cb.require_equal(
                "index1(0) == stack_pop_value(-1)",
                index1.expr(),
                step_prev.stack_pop_value.as_integer().lo(), //TODO: could be more safe if we use as_u16().value()
            );
            cb.require_equal(
                "index2(0) == stack_pop_value(-2)",
                index2.expr(),
                step_penult.stack_pop_value.as_integer().lo(),
            );
        });
        cb.require_state_transition(
            [PC, OPCODE, AUX0, AUX1]
                .into_iter()
                .map(|s| (s, Transition::Same))
                .chain(once((SP, Transition::Delta((-1).expr()))))
                .collect(),
        );
        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::VecSwapStage2);
            cb.require_cell_transition(index1.clone(), Transition::Same);
            cb.require_cell_transition(index2.clone(), Transition::Same);
        });
        VecSwapStage_1 {
            index1,
            index2,
            ref_local_sub_index,
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
        debug_assert_eq!(stage_state.step_states.len() as u64, Self::STEP_ROWS);
        debug_assert!(stage_state
            .step_states
            .iter()
            .all(|s| s.memory_ops.len() == 1));
        let index2 = stage_state.step_states[0].memory_ops[0]
            .0
            .as_ref()
            .unwrap()
            .value
            .to_fields()
            .first()
            .cloned()
            .unwrap(); // TODO: figure a better way to handle Value
        let index1 = stage_state.step_states[1].memory_ops[0]
            .0
            .as_ref()
            .unwrap()
            .value
            .to_fields()
            .first()
            .cloned()
            .unwrap(); // TODO: figure a better way to handle Value
                       // TODO: get reference's sub_index
        let ref_sub_index = stage_state.step_states[2].memory_ops[0]
            .0
            .as_ref()
            .unwrap()
            .value
            .to_fields()
            .last()
            .cloned()
            .unwrap(); // TODO: word to reference
        for i in 0..stage_state.rows() {
            self.index1
                .assign(region, offset + i, Value::known(index1))?;
            self.index2
                .assign(region, offset + i, Value::known(index2))?;
            self.ref_local_sub_index
                .assign(region, offset + i, Value::known(ref_sub_index))?;
        }
        Ok(stage_state.rows())
    }
}

/// Stage 2/3 move local value of index1/index2 to stack
#[derive(Clone)]
pub struct VecSwapStage_2_Or_3<F, const TWO: bool> {
    index1: Cell<F>,
    index2: Cell<F>,
    ref_local_sub_index: Cell<F>,
    ref_local_sub_index_extended: ExtendedSubIndex<F, 8>,
}
impl<F: Field, const TWO: bool> VecSwapStage_2_Or_3<F, TWO> {
    const PREV_STATE: ExecutionState = if TWO {
        ExecutionState::VecSwapStage1
    } else {
        ExecutionState::VecSwapStage2
    };
    const NEXT_STATE: ExecutionState = if TWO {
        ExecutionState::VecSwapStage3
    } else {
        ExecutionState::VecSwapStage4
    };
}
impl<F: Field, const TWO: bool> InstructionGadgetV2<F> for VecSwapStage_2_Or_3<F, TWO> {
    const NAME: &'static str = if TWO {
        "VecSwap_Stage_2"
    } else {
        "VecSwap_Stage_3"
    };
    const EXECUTION_STATE: ExecutionState = if TWO {
        ExecutionState::VecSwapStage2
    } else {
        ExecutionState::VecSwapStage3
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let index1 = cb.query_cell();
        let index2 = cb.query_cell();
        let ref_local_sub_index = cb.query_cell();
        let extended_sub_index = ExtendedSubIndex::construct(cb, ref_local_sub_index.expr());

        let step_curr = cb.curr.state.clone();
        cb.first_row(|cb| {
            cb.require_prev_state(Self::PREV_STATE);
        });
        cb.last_row(|cb| {
            cb.require_next_state(Self::NEXT_STATE);
        });

        cb.require_no_stack_pop();

        // --- stack push constraints
        cb.require_equal(
            "stack_push_index(0) == sp(0)+1",
            step_curr.stack_push_index.expr(),
            step_curr.sp.expr() + 1u64.expr(),
        );
        // sub_index at first row must be zero
        cb.first_row(|cb| {
            cb.require_zero(
                "stack_push_sub_index(0)==0",
                step_curr.stack_push_sub_index.expr(),
            );
        });

        cb.first_row(|cb| {
            cb.condition(step_curr.stack_push_value_header.expr(), |cb| {
                cb.require_equal(
                    "step_counter(0) == stack_push_value(0).flen",
                    step_curr.step_counter.expr(),
                    step_curr.stack_push_value.as_header().flen(),
                );
            });
            cb.condition(not::expr(step_curr.stack_push_value_header.expr()), |cb| {
                cb.require_equal(
                    "step_counter(0) == 1",
                    step_curr.step_counter.expr(),
                    1u64.expr(),
                );
            });
        });

        cb.require_equal(
            "stack_push_version(0) == clk(0)",
            step_curr.stack_push_version.expr(),
            step_curr.clk.expr(),
        );

        // -- local op constraints
        let step_prev = cb.step_state_at_offset(-1);
        cb.first_row(|cb| {
            // only need to look back on stack_pop_value for stage3
            if TWO {
                let index = Index::new(step_curr.local_frame_index.expr(), step_curr.local_index.expr());
                cb.require_equal(
                    "(local_frame_index(0), local_index(0)) == stack_pop_value(-1).as_reference().index()",
                    index.expr(),
                    step_prev.stack_pop_value.as_reference().index(),
                );
                cb.require_equal(
                    "ref_local_sub_index(0) == stack_pop_value(-1).as_reference().sub_index()",
                    ref_local_sub_index.expr(),
                    step_prev.stack_pop_value.as_reference().sub_index(),
                );
            }
        });

        cb.require_equal(
            format!("local_sub_index(0) == concat(ref_local_sub_index(0),{},nonzero(stack_push_sub_index(0)))", if TWO { "index1 + 1" } else { "index2 + 1"}),
            step_curr.local_sub_index.expr(),
            extended_sub_index.concat(
                if TWO { index1.expr() } else { index2.expr() } + 1.expr()
                    + step_curr.stack_push_sub_index.expr() * DEPTH_POW_OF_ONE_LEVEL.expr(),
            )
        );
        cb.require_zero(
            "local_read_value_invalid(0) == false",
            step_curr.local_read_value_invalid.expr(),
        );
        cb.require_equal(
            "local_read_value(0)==stack_push_value(0)",
            step_curr.local_read_value.expr(),
            step_curr.stack_push_value.expr(),
        );
        cb.require_equal(
            "local_read_value_header(0)==stack_push_value_header(0)",
            step_curr.local_read_value_header.expr(),
            step_curr.stack_push_value_header.expr(),
        );
        cb.require_true(
            "local_write_value_invalid(0) == true",
            step_curr.local_write_value_invalid.expr(),
        );
        cb.require_equal(
            "local_write_version(0) == clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );

        cb.last_row(|cb| {
            cb.require_state_transition(
                [PC, OPCODE, AUX0, AUX1]
                    .into_iter()
                    .map(|s| (s, Transition::Same))
                    .collect(),
            );
        });

        // sp = sp+1 for last row
        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Delta(1u64.expr()))]);
        });

        cb.require_cell_transition(step_curr.local_frame_index.clone(), Transition::Same);
        cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
        cb.require_cell_transition(ref_local_sub_index.clone(), Transition::Same);
        cb.require_cell_transition(index1.clone(), Transition::Same);
        cb.require_cell_transition(index2.clone(), Transition::Same);

        Self {
            index1,
            index2,
            ref_local_sub_index,
            ref_local_sub_index_extended: extended_sub_index,
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
        debug_assert_eq!(stage_state.step_states.len(), 1);

        let index1 = region.get_advice(offset, self.index1.get_column_idx(), Rotation::prev());
        let index2 = region.get_advice(offset, self.index2.get_column_idx(), Rotation::prev());
        let ref_local_sub_index = region.get_advice(
            offset,
            self.ref_local_sub_index.get_column_idx(),
            Rotation::prev(),
        );

        for (i, memory_op) in stage_state.step_states[0].memory_ops.iter().enumerate() {
            self.index1
                .assign(region, offset + i, Value::known(index1))?;
            self.index2
                .assign(region, offset + i, Value::known(index2))?;
            self.ref_local_sub_index.assign(
                region,
                offset + i,
                Value::known(ref_local_sub_index),
            )?;
            self.ref_local_sub_index_extended
                .assign(region, offset + i, ref_local_sub_index)?;
        }

        Ok(stage_state.rows())
    }
}

/// Stage 4/5 move local value of index1/index2 to stack
#[derive(Clone)]
pub struct VecSwapStage_4_Or_5<F, const FOUR: bool> {
    index1: Cell<F>,
    index2: Cell<F>,
    ref_local_sub_index: Cell<F>,
    ref_local_sub_index_extended: ExtendedSubIndex<F, 8>,
}
/// Stage 5/6 pop from stack and write to local of index1/index2
impl<F: Field, const FOUR: bool> VecSwapStage_4_Or_5<F, FOUR> {
    const PREV_STATE: ExecutionState = if FOUR {
        ExecutionState::VecSwapStage3
    } else {
        ExecutionState::VecSwapStage4
    };
}
impl<F: Field, const FOUR: bool> InstructionGadgetV2<F> for VecSwapStage_4_Or_5<F, FOUR> {
    const NAME: &'static str = if FOUR {
        "VecSwap_Stage_4"
    } else {
        "VecSwap_Stage_5"
    };
    const EXECUTION_STATE: ExecutionState = if FOUR {
        ExecutionState::VecSwapStage4
    } else {
        ExecutionState::VecSwapStage5
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let index1 = cb.query_cell();
        let index2 = cb.query_cell();
        let ref_local_sub_index = cb.query_cell();
        let extended_sub_index = ExtendedSubIndex::construct(cb, ref_local_sub_index.expr());

        let step_curr = cb.curr.state.clone();
        cb.first_row(|cb| {
            cb.require_prev_state(Self::PREV_STATE);
        });
        cb.last_row(|cb| {
            if FOUR {
                cb.require_next_state(ExecutionState::VecSwapStage5);
            }
        });
        cb.require_no_stack_push();

        // --- stack push constraints
        cb.require_equal(
            "stack_pop_index(0) == sp(0)",
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        // sub_index at first row must be zero
        cb.first_row(|cb| {
            cb.require_zero(
                "stack_pop_sub_index(0)==0",
                step_curr.stack_pop_sub_index.expr(),
            );
        });

        // value at first row must be a header
        cb.first_row(|cb| {
            cb.condition(step_curr.stack_pop_value_header.expr(), |cb| {
                cb.require_equal(
                    "step_counter(0) == stack_pop_value(0).flen",
                    step_curr.step_counter.expr(),
                    step_curr.stack_pop_value.as_header().flen(),
                );
            });
            cb.condition(not::expr(step_curr.stack_pop_value_header.expr()), |cb| {
                cb.require_equal(
                    "step_counter(0) == 1",
                    step_curr.step_counter.expr(),
                    1u64.expr(),
                );
            });
        });

        // -- local op constraints
        cb.require_equal(
            format!("local_sub_index(0) == concat(ref_local_sub_index(0),{},nonzero(stack_pop_sub_index(0)))", if FOUR { "index1 + 1" } else { "index2 + 1"}),
            step_curr.local_sub_index.expr(),
            extended_sub_index.concat(
                if FOUR { index1.expr() } else { index2.expr() } + 1.expr()
                    + step_curr.stack_pop_sub_index.expr() * DEPTH_POW_OF_ONE_LEVEL.expr(),
            )
        );

        cb.require_true(
            "local_read_value_invalid(0) == true",
            step_curr.local_read_value_invalid.expr(),
        );
        cb.require_zero(
            "local_write_value_invalid(0) == false",
            step_curr.local_write_value_invalid.expr(),
        );
        cb.require_equal(
            "stack_pop_value(0)==local_write_value(0)",
            step_curr.stack_pop_value.expr(),
            step_curr.local_write_value.expr(),
        );
        cb.require_equal(
            "local_write_value_header(0)==stack_pop_value_header(0)",
            step_curr.stack_pop_value_header.expr(),
            step_curr.local_write_value_header.expr(),
        );
        cb.require_equal(
            "local_write_version(0) == clk(0)",
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );

        if FOUR {
            cb.last_row(|cb| {
                cb.require_state_transition(
                    [PC, OPCODE, AUX0, AUX1]
                        .into_iter()
                        .map(|s| (s, Transition::Same))
                        .collect(),
                );
            });
        }
        // sp = sp-1 for last row
        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
        });

        let constraints = |cb: &mut ConstraintBuilderV2<F>| {
            cb.require_cell_transition(step_curr.local_frame_index.clone(), Transition::Same);
            cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
            cb.require_cell_transition(ref_local_sub_index.clone(), Transition::Same);
            cb.require_cell_transition(index1.clone(), Transition::Same);
            cb.require_cell_transition(index2.clone(), Transition::Same);
        };
        if FOUR {
            constraints(cb);
        } else {
            cb.not_last_row(|cb| {
                constraints(cb);
            });
        }

        Self {
            index1,
            index2,
            ref_local_sub_index,
            ref_local_sub_index_extended: extended_sub_index,
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
        debug_assert_eq!(stage_state.step_states.len(), 1);

        let index1 = region.get_advice(offset, self.index1.get_column_idx(), Rotation::prev());
        let index2 = region.get_advice(offset, self.index2.get_column_idx(), Rotation::prev());
        let ref_local_sub_index = region.get_advice(
            offset,
            self.ref_local_sub_index.get_column_idx(),
            Rotation::prev(),
        );

        for (i, memory_op) in stage_state.step_states[0].memory_ops.iter().enumerate() {
            self.index1
                .assign(region, offset + i, Value::known(index1))?;
            self.index2
                .assign(region, offset + i, Value::known(index2))?;
            self.ref_local_sub_index.assign(
                region,
                offset + i,
                Value::known(ref_local_sub_index),
            )?;
            self.ref_local_sub_index_extended
                .assign(region, offset + i, ref_local_sub_index)?;
        }

        Ok(stage_state.rows())
    }
}
