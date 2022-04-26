// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::bytecode::common::LookupBytecode;
use crate::vm_circuit::chips::bytecode::{BytecodeInterface, Opcode};
use crate::vm_circuit::chips::lookup_tables::{BytecodeLookup, RWLookup};
use crate::vm_circuit::chips::step_chip::StepChipCells;
use crate::vm_circuit::chips::utilities::*;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct CopyLoc<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BytecodeInterface<F> for CopyLoc<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::CopyLoc.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            + 1.expr();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 2.expr();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("call index", cond.clone() * call_index_expr),
            ("gc", cond.clone() * gc_expr),
        ]);

        let (read, write) = RWLookup::locals_copy(
            cells.gc.expression.clone(),
            cells.call_index.expression.clone(),
            cells.locals_index.expression.clone(),
            cells.stack_size.expression.clone(),
            cells.value_a.expression.clone(),
        );

        rw_lookups.push((read, cond.clone()));
        rw_lookups.push((write, cond.clone()));
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::CopyLoc,
            cells.locals_index.expression.clone(),
            bytecode_lookups,
            cond,
        );
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_table: &RWLookUpTable<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let op = rw_table.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_a.assign(region, offset, op.value().value())?;
        Ok(())
    }
}
