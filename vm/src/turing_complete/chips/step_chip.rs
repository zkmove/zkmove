// Copyright (c) zkMove Authors

use crate::turing_complete::chips::commons::*;
use halo2::arithmetic::FieldExt;
use halo2::plonk::{Advice, Column, ConstraintSystem, Expression, Selector};
use std::collections::VecDeque;

pub struct StepConfig {
    advice: [Column<Advice>; STEP_CHIP_WIDTH],
    s_step: Selector,
}

pub struct StepChip<F: FieldExt> {
    pub cells: StepChipCells<F>,
    pub config: StepConfig,
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

        let chip_cells = StepChipCells {
            pc: cells.pop_front().unwrap(),
            stack_size: cells.pop_front().unwrap(),
            call_index: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),

            value_a: cells.pop_front().unwrap(),
            value_b: cells.pop_front().unwrap(),
            value_c: cells.pop_front().unwrap(),

            conditions: cells.drain(0..Bytecode::amount()).collect(),
        };

        // next config each execution path of the step
    }
}
