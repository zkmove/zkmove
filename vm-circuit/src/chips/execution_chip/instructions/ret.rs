// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::LookupBytecode;
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::{Expr, SubInvert};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use proof_system::halo2_proofs::arithmetic::FieldExt;
use proof_system::halo2_proofs::circuit::Region;
use proof_system::halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct Ret<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for Ret<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        _rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::Ret.index()].expression.clone();
        let call_index = cells.call_index.expression.clone();
        let inverse = cells.auxiliary.expression.clone();

        // todo:
        // if call_index != 0, the next step will be a normal bytecode, we have
        // call_index * inverse(call_index) == 1
        // next_pc == ?
        // let pc_expr = (call_index * inverse - 1.expr()) - (cells.next_pc.expression.clone() - cells.pc.expression.clone() - 1.expr());

        // if call_index == 0, the next step will be 'Nop' or 'Stop', we have
        // call_index * inverse(call_index) == 0
        // next_pc == pc
        let call_index_expr =
            call_index.clone() * (call_index.clone() * inverse.clone() - 1.expr());
        let pc_expr = (call_index * inverse - 1.expr())
            * (cells.next_pc.expression.clone() - cells.pc.expression.clone());

        // gc should not change
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone();
        constraints.append(&mut vec![
            ("call_index", cond.clone() * call_index_expr),
            ("pc", cond.clone() * pc_expr),
            ("gc", cond.clone() * gc_expr),
        ]);
        LookupBytecode::lookup_bytecode(cells, Opcode::Ret, 0.expr(), bytecode_lookups, cond);
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        _rw_table: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        cells
            .auxiliary
            .assign(region, offset, (step.call_index as usize).sub_invert(0))?;

        Ok(())
    }
}
