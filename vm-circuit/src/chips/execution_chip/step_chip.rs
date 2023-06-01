// Copyright (c) zkMove Authors
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::{STEP_CHIP_WIDTH, STEP_HEIGHT};
use crate::chips::execution_chip::utils::dynamic_selector_half::DynamicSelectorHalf;
use crate::chips::execution_chip::utils::{CellManager, CellType};
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Chip, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression};
use std::marker::PhantomData;

//context_id, pc, stack_size, frame_index, locals_index, gc, auxiliary_1, auxiliary_2, auxiliary_3, auxiliary_4, auxiliary_5, module_index, func_index
pub const NUM_OF_STEP_STATE: usize = 13;

#[derive(Clone, Debug)]
pub struct StepChipCells<F: FieldExt> {
    pub context_id: Cell<F>,
    pub pc: Cell<F>,
    pub stack_size: Cell<F>,
    pub frame_index: Cell<F>,
    pub locals_index: Cell<F>,
    pub gc: Cell<F>,
    pub module_index: Cell<F>,
    pub function_index: Cell<F>,
    pub auxiliary_1: Cell<F>,
    pub auxiliary_2: Cell<F>,
    pub auxiliary_3: Cell<F>,
    pub auxiliary_4: Cell<F>,
    pub auxiliary_5: Cell<F>,

    pub(crate) conditions: DynamicSelectorHalf<F>,
}
impl<F: FieldExt> StepChipCells<F> {
    pub(crate) fn opcode_selector(
        &self,
        opcodes: impl IntoIterator<Item = Opcode>,
    ) -> Expression<F> {
        self.conditions
            .selector(opcodes.into_iter().map(|op| op.index()))
    }
}

#[derive(Debug, Clone)]
pub struct StepConfig<F: FieldExt> {
    pub cells: StepChipCells<F>,
    pub cell_manager: CellManager<F>,
}

#[derive(Debug, Clone)]
pub struct StepChip<F: FieldExt> {
    pub config: StepConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for StepChip<F> {
    type Config = StepConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> StepChip<F> {
    // pub(crate) fn conditions_selector(
    //     &self,
    //     opcode: Opcode,
    // ) -> Expression<F> {
    //     self.config.cells.conditions[opcode.index()].expression.clone()
    // }

    pub fn construct(
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; STEP_CHIP_WIDTH],
        offset: usize,
        is_next: bool,
    ) -> <Self as Chip<F>>::Config {
        // state fields and conditions.
        let step_state_height =
            ((NUM_OF_STEP_STATE + Opcode::total_numbers()) + STEP_CHIP_WIDTH - 1) / STEP_CHIP_WIDTH;
        // dynamic alloc cells with CellManager for opcode
        let height = if is_next {
            step_state_height // Query only the state of the next step.
        } else {
            STEP_HEIGHT // Query the entire current step.
        };
        let mut cell_manager = CellManager::new(meta, height, &advices, offset);
        let cells = {
            StepChipCells {
                context_id: cell_manager.alloc_cell(CellType::CustomGate),
                pc: cell_manager.alloc_cell(CellType::CustomGate),
                stack_size: cell_manager.alloc_cell(CellType::CustomGate),
                frame_index: cell_manager.alloc_cell(CellType::CustomGate),
                locals_index: cell_manager.alloc_cell(CellType::CustomGate),
                gc: cell_manager.alloc_cell(CellType::CustomGate),
                module_index: cell_manager.alloc_cell(CellType::CustomGate),
                function_index: cell_manager.alloc_cell(CellType::CustomGate),
                auxiliary_1: cell_manager.alloc_cell(CellType::CustomGate),
                auxiliary_2: cell_manager.alloc_cell(CellType::CustomGate),
                auxiliary_3: cell_manager.alloc_cell(CellType::CustomGate),
                auxiliary_4: cell_manager.alloc_cell(CellType::CustomGate),
                auxiliary_5: cell_manager.alloc_cell(CellType::CustomGate),

                conditions: DynamicSelectorHalf::new(&mut cell_manager, Opcode::total_numbers()),
            }
        };

        // enable equality for gc column, because we will copy last gc cell to memory chip.
        meta.enable_equality(cells.gc.column);

        StepConfig {
            cells,
            cell_manager,
        }
    }
    //
    // // step condition must be 1 or 0, and sum of all conditions must be 1
    // pub(crate) fn constrain_step_conditions(
    //     cells: &StepChipCells<F>,
    //     constraints: &mut Vec<(&str, Expression<F>)>,
    // ) {
    //     let one = Expression::Constant(F::one());
    //
    //     let mut zero_or_one = cells
    //         .conditions
    //         .iter()
    //         .map(|cell| {
    //             (
    //                 "zero or one",
    //                 (cell.expression.clone() - one.clone()) * cell.expression.clone(),
    //             )
    //         })
    //         .collect::<Vec<_>>();
    //     constraints.append(&mut zero_or_one);
    //
    //     let sum_to_one = cells
    //         .conditions
    //         .iter()
    //         .fold(one, |acc, cell| acc - cell.expression.clone());
    //     constraints.push(("sum to one", sum_to_one));
    // }

    // assign each cell of the step, return assigned cell for gc
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        _rw_operations: &RWOperations<F>,
    ) -> Result<Option<AssignedCell<F, F>>, Error> {
        self.config
            .cells
            .context_id
            .assign(region, offset, Some(F::from_u128(step.context_id)))?;

        // assign step states
        self.config
            .cells
            .pc
            .assign(region, offset, Some(F::from(step.pc as u64)))?;
        self.config.cells.stack_size.assign(
            region,
            offset,
            Some(F::from(step.stack_size as u64)),
        )?;
        self.config.cells.frame_index.assign(
            region,
            offset,
            Some(F::from(step.frame_index as u64)),
        )?;
        self.config.cells.locals_index.assign(
            region,
            offset,
            Some(F::from(step.locals_index as u64)),
        )?;
        let gc_assigned_cell =
            self.config
                .cells
                .gc
                .assign(region, offset, Some(F::from(step.gc as u64)))?;
        self.config.cells.module_index.assign(
            region,
            offset,
            Some(F::from(step.module_index as u64)),
        )?;
        self.config.cells.function_index.assign(
            region,
            offset,
            Some(F::from(step.function_index as u64)),
        )?;

        // assign conditions
        self.config
            .cells
            .conditions
            .assign(region, offset, step.opcode.index())?;

        // assign other cells for the step
        // step.opcode
        //    .assign(region, offset, step, rw_operations, &self.config.cells)?;

        Ok(Some(gc_assigned_cell))
    }
}
