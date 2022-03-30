// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::bytecode::{BytecodeInterface, Opcode};
use crate::vm_circuit::chips::lookup_tables::RWLookup;
use crate::vm_circuit::chips::step_chip::StepChipCells;
use crate::vm_circuit::chips::utilities::Expr;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::prelude::*;
use std::marker::PhantomData;

pub struct BrFalse<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BytecodeInterface<F> for BrFalse<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::BrFalse.index()].expression.clone();

        // branch target is assigned in the auxiliary, condition is popped form stack as value_a
        let aux = cells.auxiliary.expression.clone();
        let value_a = cells.value_a.expression.clone();
        let pc = cells.pc.expression.clone();
        let next_pc = cells.next_pc.expression.clone();
        // auxiliary * (1 - value_a) + (pc + 1) * value_a - next_pc = 0
        let pc_expr = aux * (1.expr() - value_a.clone()) + (pc + 1.expr()) * value_a - next_pc;

        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - 1.expr();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 1.expr();

        constraints.append(&mut vec![
            ("BrFalse pc", cond.clone() * pc_expr),
            ("BrFalse stack size", cond.clone() * stack_size_expr),
            ("BrFalse call index", cond.clone() * call_index_expr),
            ("BrFalse gc", cond.clone() * gc_expr),
        ]);

        rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                cells.value_a.expression.clone(),
            ),
            cond,
        ));
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_table: &RWLookUpTable<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        // assign next_pc into the auxiliary
        let aux_value = step.auxiliary.as_ref().ok_or_else(|| {
            error!("auxiliary is None");
            Error::Synthesis
        })?;
        cells.auxiliary.assign(region, offset, aux_value.value())?;

        let op = rw_table.0.get(step.gc).ok_or_else(|| {
            error!("gc is is None");
            Error::Synthesis
        })?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_a.assign(region, offset, op.value().value())?;
        Ok(())
    }
}
