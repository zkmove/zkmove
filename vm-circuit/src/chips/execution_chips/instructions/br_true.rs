// Copyright (c) zkMove Authors

use crate::chips::execution_chips::instructions::common::LookupBytecode;
use crate::chips::execution_chips::instructions::Instructions;
use crate::chips::execution_chips::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chips::opcode::Opcode;
use crate::chips::execution_chips::step_chip::StepChipCells;
use crate::chips::utilities::Expr;
use crate::circuit_inputs::execution_steps::ExecutionStep;
use crate::circuit_inputs::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::prelude::*;
use std::marker::PhantomData;

pub struct BrTrue<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for BrTrue<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::BrTrue.index()].expression.clone();

        // branch target is assigned in the auxiliary, condition is popped form stack as value_a
        let aux = cells.auxiliary.expression.clone();
        let value_a = cells.value_a.expression.clone();
        let pc = cells.pc.expression.clone();
        let next_pc = cells.next_pc.expression.clone();
        // auxiliary * value_a + (pc + 1) * (1 - value_a) - next_pc = 0
        let pc_expr = aux * value_a.clone() + (pc + 1.expr()) * (1.expr() - value_a) - next_pc;

        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - 1.expr();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 1.expr();

        constraints.append(&mut vec![
            ("BrTrue pc", cond.clone() * pc_expr),
            ("BrTrue stack size", cond.clone() * stack_size_expr),
            ("BrTrue call index", cond.clone() * call_index_expr),
            ("BrTrue gc", cond.clone() * gc_expr),
        ]);

        rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                cells.value_a.expression.clone(),
            ),
            cond.clone(),
        ));

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::BrTrue,
            cells.auxiliary.expression.clone(),
            bytecode_lookups,
            cond,
        );
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        // assign next_pc into the auxiliary
        let aux_value = step.auxiliary.as_ref().ok_or_else(|| {
            error!("auxiliary is None");
            Error::Synthesis
        })?;
        cells.auxiliary.assign(region, offset, aux_value.value())?;

        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_a.assign(region, offset, op.value().value())?;
        Ok(())
    }
}
