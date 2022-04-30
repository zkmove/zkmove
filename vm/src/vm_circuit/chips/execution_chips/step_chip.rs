// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::execution_chips::lookup_tables::{BytecodeLookupTable, RWTable};
use crate::vm_circuit::chips::execution_chips::opcode::Opcode;
use crate::vm_circuit::chips::utilities::*;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Chip, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use std::collections::VecDeque;
use std::marker::PhantomData;

pub const STEP_CHIP_WIDTH: usize = 10;
pub const STEP_HEIGHT: usize = 7;
pub const NUM_OF_STEP_STATE: usize = 8; //pc, stack_size, call_index, locals_index, gc, auxiliary, module_index, func_index
pub const MAX_OPERANDS_PER_STEP: usize = 3; //value_a, value_b, value_c
pub const MAX_NUM_OF_ARGUMENTS: usize = 10; //todo: dynamic configure according to the real argument number

#[derive(Clone, Debug)]
pub struct StepChipCells<F: FieldExt> {
    pub pc: Cell<F>,
    pub stack_size: Cell<F>,
    pub call_index: Cell<F>,
    pub locals_index: Cell<F>,
    pub gc: Cell<F>,
    pub module_index: Cell<F>,
    pub function_index: Cell<F>,
    pub auxiliary: Cell<F>,

    pub conditions: Vec<Cell<F>>,

    pub value_a: Cell<F>,
    pub value_b: Cell<F>,
    pub value_c: Cell<F>,

    pub args: Vec<Cell<F>>,
    pub args_mask: Vec<Cell<F>>,

    pub next_pc: Cell<F>,
    pub next_stack_size: Cell<F>,
    pub next_call_index: Cell<F>,
    pub next_locals_index: Cell<F>,
    pub next_gc: Cell<F>,
    pub next_module_index: Cell<F>,
    pub next_function_index: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct StepConfig<F: FieldExt> {
    pub advices: [Column<Advice>; STEP_CHIP_WIDTH],
    pub cells: StepChipCells<F>,
    pub s_step: Selector,
}

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
        rw_table: &RWTable,
        bytecode_table: &BytecodeLookupTable,
    ) -> <Self as Chip<F>>::Config {
        // query advice for each state of the step
        let cell_amount = NUM_OF_STEP_STATE
            + MAX_OPERANDS_PER_STEP
            + Opcode::total_numbers()
            + MAX_NUM_OF_ARGUMENTS * 2;
        let mut cells = VecDeque::with_capacity(cell_amount);
        meta.create_gate("step", |meta| {
            for i in 0..cell_amount {
                let column_index = i % STEP_CHIP_WIDTH;
                let rotation = i / STEP_CHIP_WIDTH;
                cells.push_back(Cell::new(meta, advices[column_index], rotation as i32))
            }

            // remember cells of the states of the next step
            for i in 0..NUM_OF_STEP_STATE {
                let column_index = i % STEP_CHIP_WIDTH;
                let rotation = i / STEP_CHIP_WIDTH + STEP_HEIGHT;
                cells.push_back(Cell::new(meta, advices[column_index], rotation as i32))
            }
            vec![Expression::Constant(F::zero())]
        });

        let cells = StepChipCells {
            pc: cells.pop_front().unwrap(),
            stack_size: cells.pop_front().unwrap(),
            call_index: cells.pop_front().unwrap(),
            locals_index: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),
            module_index: cells.pop_front().unwrap(),
            function_index: cells.pop_front().unwrap(),
            auxiliary: cells.pop_front().unwrap(),

            conditions: cells.drain(0..Opcode::total_numbers()).collect(),

            value_a: cells.pop_front().unwrap(),
            value_b: cells.pop_front().unwrap(),
            value_c: cells.pop_front().unwrap(),

            args: cells.drain(0..MAX_NUM_OF_ARGUMENTS).collect(),
            args_mask: cells.drain(0..MAX_NUM_OF_ARGUMENTS).collect(),

            next_pc: cells.pop_front().unwrap(),
            next_stack_size: cells.pop_front().unwrap(),
            next_call_index: cells.pop_front().unwrap(),
            next_locals_index: cells.pop_front().unwrap(),
            next_gc: cells.pop_front().unwrap(),
            next_module_index: cells.pop_front().unwrap(),
            next_function_index: cells.pop_front().unwrap(),
        };

        // config each execution path of the step
        let mut constraints = Vec::new();
        let mut rw_lookups = Vec::new();
        let mut bytecode_lookups = Vec::new();
        StepChip::constrain_step_conditions(&cells, &mut constraints);
        Opcode::iter().for_each(|opcode| {
            opcode.configure(
                &cells,
                &mut constraints,
                &mut rw_lookups,
                &mut bytecode_lookups,
            )
        });

        let s_step = meta.complex_selector();

        // for (i, constraint) in constraints.iter().enumerate() {
        //     debug!("constraint {}, {:?}", i, constraint);
        // }
        meta.create_gate("constrain step", |meta| {
            let s_step = meta.query_selector(s_step);
            constraints
                .into_iter()
                .map(move |(name, constraint)| (name, s_step.clone() * constraint))
        });

        for (lookup, cond) in rw_lookups {
            meta.lookup(|meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.gc * cond.clone(),
                        rw_table.gc_column,
                    ),
                    (
                        s_step.clone() * lookup.rw_target * cond.clone(),
                        rw_table.rw_target_column,
                    ),
                    (
                        s_step.clone() * lookup.rw * cond.clone(),
                        rw_table.rw_column,
                    ),
                    (
                        s_step.clone() * lookup.call_index * cond.clone(),
                        rw_table.call_index_column,
                    ),
                    (
                        s_step.clone() * lookup.address * cond.clone(),
                        rw_table.address_column,
                    ),
                    (s_step * lookup.value * cond, rw_table.value_column),
                ]
            });
        }

        for (lookup, cond) in bytecode_lookups {
            meta.lookup(|meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.module_index * cond.clone(),
                        bytecode_table.module_index_column,
                    ),
                    (
                        s_step.clone() * lookup.function_index * cond.clone(),
                        bytecode_table.function_index_column,
                    ),
                    (
                        s_step.clone() * lookup.pc * cond.clone(),
                        bytecode_table.pc_column,
                    ),
                    (
                        s_step.clone() * lookup.opcode * cond.clone(),
                        bytecode_table.opcode_column,
                    ),
                    (
                        s_step * lookup.operand * cond.clone(),
                        bytecode_table.operand_column,
                    ),
                ]
            });
        }

        StepConfig {
            advices,
            cells,
            s_step,
        }
    }

    // step condition must be 1 or 0, and sum of all conditions must be 1
    fn constrain_step_conditions(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
    ) {
        let one = Expression::Constant(F::one());

        let mut zero_or_one = cells
            .conditions
            .iter()
            .map(|cell| {
                (
                    "zero or one",
                    (cell.expression.clone() - one.clone()) * cell.expression.clone(),
                )
            })
            .collect::<Vec<_>>();
        constraints.append(&mut zero_or_one);

        let sum_to_one = cells
            .conditions
            .iter()
            .fold(one, |acc, cell| acc - cell.expression.clone());
        constraints.push(("sum to one", sum_to_one));
    }

    // assign each cell of the step
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_table: &RWLookUpTable<F>,
    ) -> Result<(), Error> {
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
        self.config.cells.call_index.assign(
            region,
            offset,
            Some(F::from(step.call_index as u64)),
        )?;
        self.config.cells.locals_index.assign(
            region,
            offset,
            Some(F::from(step.locals_index as u64)),
        )?;
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
            .iter()
            .enumerate()
            .for_each(|(index, cell)| {
                let condition = if step.opcode.index() == index {
                    F::one()
                } else {
                    F::zero()
                };
                let _assigned = cell.assign(region, offset, Some(condition));
            });

        // assign other cells for the step
        step.opcode
            .assign(region, offset, step, rw_table, &self.config.cells)?;

        Ok(())
    }
}
