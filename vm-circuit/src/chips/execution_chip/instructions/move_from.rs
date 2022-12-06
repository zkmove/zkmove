// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::LookupBytecode;
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct MoveFrom<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for MoveFrom<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::MoveFrom.index()]
            .expression
            .clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cells.next_stack_size.expression.clone();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 3.expr();
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
                cells.value_a.expression.clone(), //address
            ),
            cond.clone(),
        ));

        rw_lookups.push((
            RWLookup::global_move_from(
                cells.gc.expression.clone() + 1.expr(),
                cells.value_a.expression.clone(), //address
                cells.value_b.expression.clone(),
                cells.auxiliary.expression.clone(), //sd_index
            ),
            cond.clone(),
        ));

        rw_lookups.push((
            RWLookup::stack_push(
                cells.gc.expression.clone() + 2.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                cells.value_b.expression.clone(),
            ),
            cond.clone(),
        ));

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::MoveFrom,
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
        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_a.assign(region, offset, op.value().value())?;

        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_b.assign(region, offset, op.value().value())?;
        cells
            .auxiliary
            .assign(region, offset, Some(F::from_u128(op.sd_index() as u128)))?;

        Ok(())
    }
}
