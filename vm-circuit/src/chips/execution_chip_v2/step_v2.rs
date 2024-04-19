use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::{Cell, CellManager, CellType};
use crate::utils::cell_placement_strategy::{
    CMFixedWidthStrategy, CMFixedWidthStrategyDistribution,
};
use gadgets::util::Expr;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{ConstraintSystem, Error, Expression};
use std::iter;
use strum::IntoEnumIterator;
use types::Field;

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
    pub stack_pop_value: Cell<F>,
    pub stack_pop_value_flag: Cell<F>,
    pub stack_pop_version: Cell<F>,

    pub stack_push_index: Cell<F>,
    pub stack_push_sub_index: Cell<F>,
    pub stack_push_value: Cell<F>,
    pub stack_push_value_flag: Cell<F>,
    pub stack_push_version: Cell<F>,

    pub local_frame_index: Cell<F>,
    pub local_index: Cell<F>,
    pub local_sub_index: Cell<F>,
    pub local_read_value: Cell<F>,
    pub local_read_value_flag: Cell<F>,
    pub local_read_version: Cell<F>,

    pub local_write_value: Cell<F>,
    pub local_write_value_flag: Cell<F>,
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
}

#[derive(Debug, Clone)]
pub struct Step<F> {
    pub state: StepState<F>,
    pub cell_manager: CellManager<CMFixedWidthStrategy>,
}

impl<F: Field> Step<F> {
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        advices: CMFixedWidthStrategyDistribution,
        offset: isize,
    ) -> Self {
        // height should always be 1
        let strategy = CMFixedWidthStrategy::new(advices, offset).with_max_height(1);

        let mut cell_manager = CellManager::new(strategy);

        let clk = cell_manager.query_cell(meta, CellType::StoragePhase1);
        let stack_pop_version = cell_manager.query_cell(meta, CellType::StoragePhase1);
        let state = StepState {
            clk,
            frame_index: cell_manager.query_cell(meta, CellType::StoragePhase1),
            module_index: cell_manager.query_cell(meta, CellType::StoragePhase1),
            function_index: cell_manager.query_cell(meta, CellType::StoragePhase1),
            pc: cell_manager.query_cell(meta, CellType::StoragePhase1),
            sp: cell_manager.query_cell(meta, CellType::StoragePhase1),
            opcode: cell_manager.query_cell(meta, CellType::StoragePhase1),
            aux0: cell_manager.query_cell(meta, CellType::StoragePhase1),
            aux1: cell_manager.query_cell(meta, CellType::StoragePhase1),
            step_counter: cell_manager.query_cell(meta, CellType::StoragePhase1),

            stack_pop_index: cell_manager.query_cell(meta, CellType::StoragePhase1),
            stack_pop_sub_index: cell_manager.query_cell(meta, CellType::StoragePhase1),
            stack_pop_value: cell_manager.query_cell(meta, CellType::StoragePhase1),
            stack_pop_value_flag: cell_manager.query_cell(meta, CellType::StoragePhase1),
            stack_pop_version,

            stack_push_index: cell_manager.query_cell(meta, CellType::StoragePhase1),
            stack_push_sub_index: cell_manager.query_cell(meta, CellType::StoragePhase1),
            stack_push_value: cell_manager.query_cell(meta, CellType::StoragePhase1),
            stack_push_value_flag: cell_manager.query_cell(meta, CellType::StoragePhase1),
            stack_push_version: cell_manager.query_cell(meta, CellType::StoragePhase1),

            local_frame_index: cell_manager.query_cell(meta, CellType::StoragePhase1),
            local_index: cell_manager.query_cell(meta, CellType::StoragePhase1),
            local_sub_index: cell_manager.query_cell(meta, CellType::StoragePhase1),
            local_read_value: cell_manager.query_cell(meta, CellType::StoragePhase1),
            local_read_value_flag: cell_manager.query_cell(meta, CellType::StoragePhase1),
            local_read_version: cell_manager.query_cell(meta, CellType::StoragePhase1),
            local_write_value: cell_manager.query_cell(meta, CellType::StoragePhase1),
            local_write_value_flag: cell_manager.query_cell(meta, CellType::StoragePhase1),
            local_write_version: cell_manager.query_cell(meta, CellType::StoragePhase1),

            execution_state: DynamicSelectorHalf::new(
                meta,
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
        cell_manager: &mut CellManager<CMFixedWidthStrategy>,
        count: usize,
    ) -> Self {
        let target_pairs = cell_manager.query_cells(meta, CellType::StoragePhase1, (count + 1) / 2);
        let target_odd = cell_manager.query_cell(meta, CellType::StoragePhase1);
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
            Value::known(if odd { F::ONE } else { F::ZERO }),
        )?;
        for (index, cell) in self.target_pairs.iter().enumerate() {
            cell.assign(
                region,
                offset,
                Value::known(if index == pair_index { F::ONE } else { F::ZERO }),
            )?;
        }
        Ok(())
    }
}
