// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::bytecode::common::LoadOp;
use crate::vm_circuit::chips::bytecode::{BytecodeInterface, Opcode};
use crate::vm_circuit::chips::lookup_tables::RWLookup;
use crate::vm_circuit::chips::step_chip::StepChipCells;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct LdU8<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BytecodeInterface<F> for LdU8<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
    ) {
        //LdU8
        let cond = cells.conditions[Opcode::LdU8.index()].expression.clone();
        LoadOp::constrain_ld_op(cells, constraints, cond.clone());
        LoadOp::lookup_ld_op(cells, rw_lookups, cond);
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_table: &RWLookUpTable<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let op = rw_table.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        cells.value_a.assign(region, offset, op.value().value())?;
        Ok(())
    }
}
