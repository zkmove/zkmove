// Copyright (c) zkMove Authors

use crate::turing_complete::chips::arithmetic::ArithmeticChip;
use crate::turing_complete::chips::commons::*;
use crate::turing_complete::chips::ld::LdChip;
use crate::turing_complete::chips::pop::PopChip;
use crate::turing_complete::chips::vm_circuit::RWTable;
use crate::turing_complete::circuit_inputs::{ExecutionStep, RWLookUpTable, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Chip, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use logger::prelude::*;
use std::collections::VecDeque;
use std::marker::PhantomData;

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
    ) -> <Self as Chip<F>>::Config {
        // query advice for each state of the step
        let cell_amount = NUM_OF_STEP_STATE + MAX_OPERANDS_PER_STEP + NUMBER_OF_BYTECODE_MEMBERS;
        let mut cells = VecDeque::with_capacity(cell_amount);
        meta.create_gate("step", |meta| {
            for i in 0..cell_amount {
                let column_index = i % STEP_CHIP_WIDTH;
                let rotation = i / STEP_CHIP_WIDTH;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            // remember cells of the states of the next step
            for i in 0..NUM_OF_STEP_STATE {
                let column_index = i % STEP_CHIP_WIDTH;
                let rotation = i / STEP_CHIP_WIDTH + STEP_HEIGHT;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }
            vec![Expression::Constant(F::zero())]
        });

        let cells = StepChipCells {
            pc: cells.pop_front().unwrap(),
            stack_size: cells.pop_front().unwrap(),
            call_index: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),
            conditions: cells.drain(0..NUMBER_OF_BYTECODE_MEMBERS).collect(),

            value_a: cells.pop_front().unwrap(),
            value_b: cells.pop_front().unwrap(),
            value_c: cells.pop_front().unwrap(),

            next_pc: cells.pop_front().unwrap(),
            next_stack_size: cells.pop_front().unwrap(),
            next_call_index: cells.pop_front().unwrap(),
            next_gc: cells.pop_front().unwrap(),
        };

        debug!("{:?}", cells);

        // config each execution path of the step
        let mut constraints = Vec::new();
        let mut rw_lookups = Vec::new();
        StepChip::constrain_step_conditions(&cells, &mut constraints);
        let _arithmetic_config =
            ArithmeticChip::configure(meta, advices, &cells, &mut constraints, &mut rw_lookups);
        let _ld_config =
            LdChip::configure(meta, advices, &cells, &mut constraints, &mut rw_lookups);
        let _pop_config =
            PopChip::configure(meta, advices, &cells, &mut constraints, &mut rw_lookups);
        let s_step = meta.selector();
        meta.create_gate("constrain step", |meta| {
            let s_step = meta.query_selector(s_step);
            constraints
                .into_iter()
                .map(move |(name, constraint)| (name, s_step.clone() * constraint))
        });

        for (lookup, cond) in rw_lookups {
            meta.lookup(|meta| {
                vec![
                    (lookup.gc * cond.clone(), rw_table.gc_column),
                    (lookup.rw_target * cond.clone(), rw_table.rw_target_column),
                    (lookup.rw * cond.clone(), rw_table.rw_column),
                    (lookup.call_index * cond.clone(), rw_table.call_index_column),
                    (lookup.address * cond.clone(), rw_table.address_column),
                    (lookup.value * cond, rw_table.value_column),
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
        step: &ExecutionStep,
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
        self.config
            .cells
            .gc
            .assign(region, offset, Some(F::from(step.gc as u64)))?;

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

        // assign operands for each Opcode
        match step.opcode {
            Opcode::LdU8 => LdChip::assign(region, offset, step, rw_table, &self.config.cells)?,
            Opcode::LdU64 => LdChip::assign(region, offset, step, rw_table, &self.config.cells)?,
            Opcode::LdU128 => LdChip::assign(region, offset, step, rw_table, &self.config.cells)?,
            Opcode::Pop => PopChip::assign(region, offset, step, rw_table, &self.config.cells)?,
            Opcode::Ret => {}
            Opcode::Add => self.assign_binary_op(region, offset, step, rw_table)?,
            Opcode::Mul => self.assign_binary_op(region, offset, step, rw_table)?,
        }

        Ok(())
    }

    fn assign_binary_op(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_table: &RWLookUpTable<F>,
    ) -> Result<(), Error> {
        let op = rw_table.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        self.config
            .cells
            .value_a
            .assign(region, offset, op.value().value())?;

        let op = rw_table.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        self.config
            .cells
            .value_b
            .assign(region, offset, op.value().value())?;

        let op = rw_table.0.get(step.gc + 2).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        self.config
            .cells
            .value_c
            .assign(region, offset, op.value().value())?;

        Ok(())
    }
}
