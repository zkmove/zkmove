// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::LookupBytecode;
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::prelude::*;
use std::marker::PhantomData;

pub struct Branch<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for Branch<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        _rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::Branch.index()].expression.clone();
        // next pc is assigned in the auxiliary
        let pc_expr = cells.auxiliary.expression.clone() - cells.next_pc.expression.clone();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cells.next_stack_size.expression.clone();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone();
        constraints.append(&mut vec![
            ("branch pc", cond.clone() * pc_expr),
            ("branch stack size", cond.clone() * stack_size_expr),
            ("branch call index", cond.clone() * call_index_expr),
            ("branch gc", cond.clone() * gc_expr),
        ]);

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Branch,
            cells.auxiliary.expression.clone(),
            bytecode_lookups,
            cond,
        );
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        _rw_table: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        // assign next_pc into the auxiliary
        let aux_value = step.auxiliary.as_ref().ok_or_else(|| {
            error!("auxiliary is None");
            Error::Synthesis
        })?;
        cells.auxiliary.assign(region, offset, aux_value.value())?;
        Ok(())
    }
}
