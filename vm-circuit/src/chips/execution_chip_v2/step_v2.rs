use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::utils::to_field::{ToField, ToFields};
use crate::chips::execution_chip_v2::value::Value;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::{Cell, CellManager, CellManagerColumns, CellType};
use crate::utils::cell_placement_strategy::CMFixedHeightStrategy;
use crate::utils::challenges::Challenges;
use aptos_move_witnesses::step_state::{MemoryOp, StepState as StepStateWitness};
use gadgets::util::Expr;
use halo2_proofs::circuit::Value as Halo2Value;
use halo2_proofs::plonk::{ConstraintSystem, Error, Expression};
use std::iter;
use strum::IntoEnumIterator;
use types::Field;

pub const NUM_OF_VALUE_LIMBS: usize = 2;

pub const STEP_COUNTER: &str = "step_counter";
pub const FRAME_INDEX: &str = "frame_index";
pub const MODULE_INDEX: &str = "module_index";
pub const FUNCTION_INDEX: &str = "function_index";
pub const PC: &str = "pc";
pub const SP: &str = "sp";
pub const OPCODE: &str = "OPCODE";
pub const AUX0: &str = "aux0";
pub const AUX1: &str = "aux1";

#[derive(Clone, Debug)]
pub(crate) struct StepState<F> {
    pub clk: Cell<F>,
    pub frame_index: Cell<F>,
    pub module_index: Cell<F>,
    pub function_index: Cell<F>,
    pub pc: Cell<F>,
    pub sp: Cell<F>,
    pub opcode: Cell<F>,
    pub aux0: Cell<F>,
    pub aux1: Cell<F>,
    pub step_counter: Cell<F>,

    pub stack_pop_index: Cell<F>,
    pub stack_pop_sub_index: Cell<F>,
    pub stack_pop_value: Value<F, NUM_OF_VALUE_LIMBS>,
    pub stack_pop_value_header: Cell<F>,
    pub stack_pop_version: Cell<F>,

    pub stack_push_index: Cell<F>,
    pub stack_push_sub_index: Cell<F>,
    pub stack_push_value: Value<F, NUM_OF_VALUE_LIMBS>,
    pub stack_push_value_header: Cell<F>,
    pub stack_push_version: Cell<F>,

    pub local_frame_index: Cell<F>,
    pub local_index: Cell<F>,
    pub local_sub_index: Cell<F>,

    pub local_read_value: Value<F, NUM_OF_VALUE_LIMBS>,
    pub local_read_value_header: Cell<F>,
    pub local_read_value_invalid: Cell<F>,
    pub local_read_version: Cell<F>,

    pub local_write_value: Value<F, NUM_OF_VALUE_LIMBS>,
    pub local_write_value_header: Cell<F>,
    pub local_write_value_invalid: Cell<F>,
    pub local_write_version: Cell<F>,

    /// The execution state selector for the step
    pub(crate) execution_state: DynamicSelectorHalf<F>,
}

impl<F: Field> StepState<F> {
    pub fn execution_state_selector(
        &self,
        execution_states: impl IntoIterator<Item = ExecutionState>,
    ) -> Expression<F> {
        self.execution_state
            .selector(execution_states.into_iter().map(|s| s as usize))
    }

    pub(crate) fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        step_counter: usize,
        step_state: &StepStateWitness,
        memory_op: &MemoryOp,
    ) -> Result<(), Error> {
        self.execution_state
            .assign(region, offset, step_state.exec_state as usize)?;
        self.step_counter.assign(
            region,
            offset,
            Halo2Value::known(F::from_u128(step_counter as u128)),
        )?;

        self.clk
            .assign(region, offset, Halo2Value::known(step_state.clk.into()))?;
        self.frame_index.assign(
            region,
            offset,
            Halo2Value::known(F::from_u128(step_state.frame_index as u128)),
        )?;
        self.module_index.assign(
            region,
            offset,
            Halo2Value::known(F::from(step_state.module_index)),
        )?;
        self.function_index.assign(
            region,
            offset,
            Halo2Value::known(F::from_u128(step_state.function_index as u128)),
        )?;
        self.pc.assign(
            region,
            offset,
            Halo2Value::known(F::from_u128(step_state.pc as u128)),
        )?;
        self.sp.assign(
            region,
            offset,
            Halo2Value::known(F::from_u128(step_state.sp as u128)),
        )?;
        self.opcode.assign(
            region,
            offset,
            Halo2Value::known(F::from_u128(step_state.opcode as u128)),
        )?;

        self.aux0.assign(
            region,
            offset,
            Halo2Value::known(F::from_u128(step_state.aux0)),
        )?;
        self.aux1.assign(
            region,
            offset,
            Halo2Value::known(F::from_u128(step_state.aux1)),
        )?;

        // assign stack_pop
        {
            let stack_pop = memory_op.0.as_ref();
            self.stack_pop_index.assign(
                region,
                offset,
                Halo2Value::known(F::from(stack_pop.map(|v| v.index).unwrap_or(0))),
            )?;

            self.stack_pop_sub_index.assign(
                region,
                offset,
                Halo2Value::known(
                    stack_pop
                        .map(|v| v.sub_index.to_field())
                        .unwrap_or(F::zero()),
                ),
            )?;
            self.stack_pop_value_header.assign(
                region,
                offset,
                Halo2Value::known(
                    stack_pop
                        .map(|v| if v.value_header { F::ONE } else { F::ZERO })
                        .unwrap_or(F::ZERO),
                ),
            )?;
            self.stack_pop_version.assign(
                region,
                offset,
                Halo2Value::known(F::from(stack_pop.map(|v| v.version).unwrap_or(0))),
            )?;
            self.stack_pop_value.assign(
                region,
                offset,
                stack_pop
                    .map(|v| v.value.to_fields())
                    .unwrap_or([F::ZERO; NUM_OF_VALUE_LIMBS].to_vec()),
            )?;
        }

        // assign stack_push
        {
            let stack_push = memory_op.1.as_ref();
            self.stack_push_index.assign(
                region,
                offset,
                Halo2Value::known(F::from(stack_push.map(|v| v.index).unwrap_or(0))),
            )?;

            self.stack_push_sub_index.assign(
                region,
                offset,
                Halo2Value::known(
                    stack_push
                        .map(|v| v.sub_index.to_field())
                        .unwrap_or(F::zero()),
                ),
            )?;
            self.stack_push_value_header.assign(
                region,
                offset,
                Halo2Value::known(
                    stack_push
                        .map(|v| if v.value_header { F::ONE } else { F::ZERO })
                        .unwrap_or(F::ZERO),
                ),
            )?;
            self.stack_push_version.assign(
                region,
                offset,
                Halo2Value::known(F::from(stack_push.map(|v| v.version).unwrap_or(0))),
            )?;
            self.stack_push_value.assign(
                region,
                offset,
                stack_push
                    .map(|v| v.value.to_fields())
                    .unwrap_or([F::ZERO; NUM_OF_VALUE_LIMBS].to_vec()),
            )?;
        }
        // assign local read&write
        {
            let local_read_write = memory_op.2.as_ref();
            self.local_frame_index.assign(
                region,
                offset,
                Halo2Value::known(F::from(
                    local_read_write.map(|v| v.frame_index as u64).unwrap_or(0),
                )),
            )?;

            self.local_index.assign(
                region,
                offset,
                Halo2Value::known(F::from(
                    local_read_write.map(|v| v.index as u64).unwrap_or(0),
                )),
            )?;
            self.local_sub_index.assign(
                region,
                offset,
                Halo2Value::known(
                    local_read_write
                        .map(|v| v.sub_index.to_field())
                        .unwrap_or(F::zero()),
                ),
            )?;

            self.local_read_value.assign(
                region,
                offset,
                local_read_write
                    .map(|v| v.read_value.to_fields())
                    .unwrap_or([F::ZERO; NUM_OF_VALUE_LIMBS].to_vec()),
            )?;

            self.local_read_value_header.assign(
                region,
                offset,
                Halo2Value::known(
                    local_read_write
                        .map(|v| if v.read_value_header { F::ONE } else { F::ZERO })
                        .unwrap_or(F::ZERO),
                ),
            )?;
            self.local_read_value_invalid.assign(
                region,
                offset,
                Halo2Value::known(
                    local_read_write
                        .map(|v| {
                            if v.read_value_invalid {
                                F::ONE
                            } else {
                                F::ZERO
                            }
                        })
                        .unwrap_or(F::ZERO),
                ),
            )?;
            self.local_read_version.assign(
                region,
                offset,
                Halo2Value::known(F::from(
                    local_read_write.map(|v| v.read_version).unwrap_or(0),
                )),
            )?;

            self.local_write_value.assign(
                region,
                offset,
                local_read_write
                    .map(|v| v.write_value.to_fields())
                    .unwrap_or([F::ZERO; NUM_OF_VALUE_LIMBS].to_vec()),
            )?;
            self.local_write_value_header.assign(
                region,
                offset,
                Halo2Value::known(
                    local_read_write
                        .map(|v| {
                            if v.write_value_header {
                                F::ONE
                            } else {
                                F::ZERO
                            }
                        })
                        .unwrap_or(F::ZERO),
                ),
            )?;
            self.local_write_value_invalid.assign(
                region,
                offset,
                Halo2Value::known(
                    local_read_write
                        .map(|v| {
                            if v.write_value_invalid {
                                F::ONE
                            } else {
                                F::ZERO
                            }
                        })
                        .unwrap_or(F::ZERO),
                ),
            )?;
            self.local_write_version.assign(
                region,
                offset,
                Halo2Value::known(F::from(
                    local_read_write.map(|v| v.write_version).unwrap_or(0),
                )),
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Step<F> {
    pub state: StepState<F>,
    pub cell_manager: CellManager<CMFixedHeightStrategy>,
}

impl<F: Field> Step<F> {
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        cell_manager_columns: &mut CellManagerColumns,
        offset: isize,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        // height should always be 1
        let strategy = CMFixedHeightStrategy::new(1, offset);

        let mut cell_manager = CellManager::new(strategy, cell_manager_columns);

        let clk = cell_manager.query_cell(meta, cell_manager_columns, CellType::StoragePhase1);
        let stack_pop_version =
            cell_manager.query_cell(meta, cell_manager_columns, CellType::StoragePhase1);
        let state = StepState {
            clk,
            frame_index: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            module_index: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            function_index: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            pc: cell_manager.query_cell(meta, cell_manager_columns, CellType::StoragePhase1),
            sp: cell_manager.query_cell(meta, cell_manager_columns, CellType::StoragePhase1),
            opcode: cell_manager.query_cell(meta, cell_manager_columns, CellType::StoragePhase1),
            aux0: cell_manager.query_cell(meta, cell_manager_columns, CellType::StoragePhase1),
            aux1: cell_manager.query_cell(meta, cell_manager_columns, CellType::StoragePhase1),
            step_counter: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),

            stack_pop_index: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            stack_pop_sub_index: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            stack_pop_value: Value::new(meta, cell_manager_columns, &mut cell_manager, challenges),
            stack_pop_value_header: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            stack_pop_version,

            stack_push_index: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            stack_push_sub_index: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            stack_push_value: Value::new(meta, cell_manager_columns, &mut cell_manager, challenges),
            stack_push_value_header: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            stack_push_version: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),

            local_frame_index: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            local_index: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            local_sub_index: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            local_read_value: Value::new(meta, cell_manager_columns, &mut cell_manager, challenges),
            local_read_value_header: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            local_read_value_invalid: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            local_read_version: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            local_write_value: Value::new(
                meta,
                cell_manager_columns,
                &mut cell_manager,
                challenges,
            ),
            local_write_value_header: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            local_write_value_invalid: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),
            local_write_version: cell_manager.query_cell(
                meta,
                cell_manager_columns,
                CellType::StoragePhase1,
            ),

            execution_state: DynamicSelectorHalf::new(
                meta,
                cell_manager_columns,
                &mut cell_manager,
                ExecutionState::iter().count(),
            ),
        };
        Self {
            state,
            cell_manager,
        }
    }

    pub(crate) fn execution_state_selector(
        &self,
        execution_states: impl IntoIterator<Item = ExecutionState>,
    ) -> Expression<F> {
        self.state.execution_state_selector(execution_states)
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        step_counter: usize,
        step_state: &StepStateWitness,
        memory_op: &MemoryOp,
    ) -> Result<(), Error> {
        self.state
            .assign_exec_step(region, offset, step_counter, step_state, memory_op)
    }
}

/// Dynamic selector that generates expressions of degree 2 to select from N
/// possible targets using N/2 + 1 cells.
#[derive(Clone, Debug)]
pub(crate) struct DynamicSelectorHalf<F> {
    /// N value: how many possible targets this selector supports.
    count: usize,
    /// Whether the target is odd.  `target % 2 == 1`.
    pub(crate) target_odd: Cell<F>,
    /// Whether the target belongs to each consecutive pair of targets.
    /// `in [0, 1], in [2, 3], in [4, 5], ...`
    pub(crate) target_pairs: Vec<Cell<F>>,
}

impl<F: Field> DynamicSelectorHalf<F> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        cell_manager_columns: &mut CellManagerColumns,
        cell_manager: &mut CellManager<CMFixedHeightStrategy>,
        count: usize,
    ) -> Self {
        let target_pairs = cell_manager.query_cells(
            meta,
            cell_manager_columns,
            CellType::StoragePhase1,
            (count + 1) / 2,
        );
        let target_odd =
            cell_manager.query_cell(meta, cell_manager_columns, CellType::StoragePhase1);
        Self {
            count,
            target_pairs,
            target_odd,
        }
    }

    /// Return the list of constraints that configure this "gadget".
    pub(crate) fn configure(&self) -> Vec<(&'static str, Expression<F>)> {
        // Only one of target_pairs should be enabled
        let sum_to_one = (
            "Only one of target_pairs should be enabled",
            self.target_pairs
                .iter()
                .fold(1u64.expr(), |acc, cell| acc - cell.expr()),
        );
        // Cells representation for target_pairs and target_odd should be bool.
        let bool_checks = iter::once(&self.target_odd)
            .chain(&self.target_pairs)
            .map(|cell| {
                (
                    "Representation for target_pairs and target_odd should be bool",
                    cell.expr() * (1u64.expr() - cell.expr()),
                )
            });
        let mut constraints: Vec<(&'static str, Expression<F>)> =
            iter::once(sum_to_one).chain(bool_checks).collect();
        // In case count is odd, we must forbid selecting N+1 with (odd = 1,
        // target_pairs[-1] = 1)
        if self.count % 2 == 1 {
            constraints.push((
                "Forbid N+1 target when N is odd",
                self.target_odd.expr() * self.target_pairs[self.count / 2].expr(),
            ));
        }
        constraints
    }

    pub(crate) fn selector(&self, targets: impl IntoIterator<Item = usize>) -> Expression<F> {
        targets
            .into_iter()
            .map(|target| {
                let odd = target % 2 == 1;
                let pair_index = target / 2;
                (if odd {
                    self.target_odd.expr()
                } else {
                    1u64.expr() - self.target_odd.expr()
                }) * self.target_pairs[pair_index].expr()
            })
            .reduce(|acc, expr| acc + expr)
            .expect("Select some Targets")
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        target: usize,
    ) -> Result<(), Error> {
        let odd = target % 2 == 1;
        let pair_index = target / 2;
        self.target_odd.assign(
            region,
            offset,
            Halo2Value::known(if odd { F::ONE } else { F::ZERO }),
        )?;
        for (index, cell) in self.target_pairs.iter().enumerate() {
            cell.assign(
                region,
                offset,
                Halo2Value::known(if index == pair_index { F::ONE } else { F::ZERO }),
            )?;
        }
        Ok(())
    }
}
