// Copyright (c) zkMove Authors

use crate::turing_complete::chips::commons::*;
use crate::turing_complete::chips::lookup::RWLookup;
use crate::turing_complete::circuit_inputs::{ExecutionStep, RWLookUpTable, RW};
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column},
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
        advice: [Column<Advice>; STEP_CHIP_WIDTH],
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
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
            ("gc", cond.clone() * gc_expr),
        ]);

        rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                cells.value_a.expression.clone(),
            ),
            cond,
        ));

        PopConfig { advice }
    }

    pub fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_table: &RWLookUpTable<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let op = rw_table.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_a.assign(region, offset, op.value().value())?;
        Ok(())
    }
}
