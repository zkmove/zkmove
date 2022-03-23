// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::commons::*;
use crate::vm_circuit::chips::lookup::RWLookup;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable, RW};
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column},
};
use std::marker::PhantomData;

pub struct LdConfig {
    pub advice: [Column<Advice>; STEP_CHIP_WIDTH],
}

pub struct LdChip<F: FieldExt> {
    config: LdConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> LdChip<F> {
    pub fn constrain_ld_op(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        cond: Expression<F>,
    ) {
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            + 1.expr();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 1.expr();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("call index", cond.clone() * call_index_expr),
            ("gc", cond * gc_expr),
        ]);
    }

    pub fn lookup_ld_op(
        cells: &StepChipCells<F>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        cond: Expression<F>,
    ) {
        rw_lookups.push((
            RWLookup::stack_push(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                cells.value_a.expression.clone(),
            ),
            cond,
        ));
    }

    pub fn configure(
        advice: [Column<Advice>; STEP_CHIP_WIDTH],
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
    ) -> LdConfig {
        // for column in &advice {
        //     meta.enable_equality((*column).into());
        // }

        //LdU8
        let cond = cells.conditions[Opcode::LdU8.index()].expression.clone();
        LdChip::constrain_ld_op(cells, constraints, cond.clone());
        LdChip::lookup_ld_op(cells, rw_lookups, cond);

        //LdU64
        let cond = cells.conditions[Opcode::LdU64.index()].expression.clone();
        LdChip::constrain_ld_op(cells, constraints, cond.clone());
        LdChip::lookup_ld_op(cells, rw_lookups, cond);

        //LdU128
        let cond = cells.conditions[Opcode::LdU128.index()].expression.clone();
        LdChip::constrain_ld_op(cells, constraints, cond.clone());
        LdChip::lookup_ld_op(cells, rw_lookups, cond);

        LdConfig { advice }
    }

    pub fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_table: &RWLookUpTable<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let op = rw_table.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        cells.value_a.assign(region, offset, op.value().value())?;
        Ok(())
    }
}
