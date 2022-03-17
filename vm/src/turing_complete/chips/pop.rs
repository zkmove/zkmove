// Copyright (c) zkMove Authors

use crate::turing_complete::chips::commons::*;
use crate::turing_complete::circuit_inputs::{ExecutionStep, RWLookUpTable, RW};
use halo2::circuit::Region;
use halo2::plonk::{Error, Expression};
use halo2::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem},
};
use std::marker::PhantomData;

pub struct PopConfig {
    pub advice: [Column<Advice>; STEP_CHIP_WIDTH],
}

pub struct PopChip<F: FieldExt> {
    config: PopConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> PopChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; STEP_CHIP_WIDTH],
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
    ) -> PopConfig {
        // for column in &advice {
        //     meta.enable_equality((*column).into());
        // }

        let cond = cells.conditions[Opcode::Pop.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - 1.expr();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 1.expr();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("call index", cond.clone() * call_index_expr),
            ("gc", cond * gc_expr),
        ]);

        PopConfig { advice }
    }

    pub fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_table: &RWLookUpTable<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let op = rw_table.0.get(step.gc).ok_or(Error::SynthesisError)?;
        debug_assert!(op.rw() == RW::READ);
        cells
            .value_a
            .assign(region, offset, op.rw_value().value())?;
        Ok(())
    }
}
