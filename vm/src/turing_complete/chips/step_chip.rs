// Copyright (c) zkMove Authors

use crate::turing_complete::chips::arithmetic::ArithmeticChip;
use crate::turing_complete::chips::commons::*;
use halo2::arithmetic::FieldExt;
use halo2::plonk::{Advice, Column, ConstraintSystem, Expression, Selector};
use std::collections::VecDeque;

pub struct StepConfig<F: FieldExt> {
    pub advices: [Column<Advice>; STEP_CHIP_WIDTH],
    pub cells: StepChipCells<F>,
    pub s_step: Selector,
}

pub struct StepChip<F: FieldExt> {
    pub config: StepConfig<F>,
}

impl<F: FieldExt> StepChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; STEP_CHIP_WIDTH],
    ) -> Self {
        // query advice for each state of the step
        let cell_amount = NUM_OF_STEP_STATE + MAX_OPERANDS_PER_STEP + Bytecode::amount();
        let mut cells = VecDeque::with_capacity(cell_amount);
        meta.create_gate("step", |meta| {
            for i in 0..cell_amount {
                let column_index = i % STEP_CHIP_WIDTH;
                let rotation = i / STEP_CHIP_WIDTH;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }
            vec![Expression::Constant(F::zero())]
        });

        let cells = StepChipCells {
            pc: cells.pop_front().unwrap(),
            stack_size: cells.pop_front().unwrap(),
            call_index: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),

            value_a: cells.pop_front().unwrap(),
            value_b: cells.pop_front().unwrap(),
            value_c: cells.pop_front().unwrap(),

            conditions: cells.drain(0..Bytecode::amount()).collect(),
        };

        // next to config each execution path of the step
        let mut constraints = Vec::new();
        StepChip::constrain_step_conditions(&cells, &mut constraints);
        let _arithmetic_config = ArithmeticChip::configure(meta, advices, &cells, &mut constraints);

        let s_step = meta.selector();
        meta.create_gate("step", |meta| {
            let s_step = meta.query_selector(s_step);
            constraints
                .into_iter()
                .map(move |constraint| s_step.clone() * constraint)
        });

        StepChip {
            config: StepConfig {
                advices,
                cells,
                s_step,
            },
        }
    }

    // step condition must be 1 or 0, and sum of all conditions must be 1
    fn constrain_step_conditions(cells: &StepChipCells<F>, constraints: &mut Vec<Expression<F>>) {
        let one = Expression::Constant(F::one());

        let mut zero_or_one = cells
            .conditions
            .iter()
            .map(|cell| (cell.expression.clone() - one.clone()) * cell.expression.clone())
            .collect::<Vec<_>>();
        constraints.append(&mut zero_or_one);

        let sum_to_one = cells
            .conditions
            .iter()
            .fold(one, |acc, cell| acc - cell.expression.clone());
        constraints.push(sum_to_one);
    }
}
