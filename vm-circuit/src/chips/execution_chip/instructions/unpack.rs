// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{BytecodeLookup, RWLookup, RWTarget};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::{StepChipCells, MAX_NUM_OF_ARGUMENTS};
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::prelude::*;
use std::marker::PhantomData;

pub struct Unpack<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for Unpack<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        _bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        //Unpack
        let cond = cells.conditions[Opcode::Unpack.index()].expression.clone();
        let field_num = cells.auxiliary.expression.clone();
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            + field_num.clone()
            - 1.expr();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + field_num.clone()
            + 1.expr();
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
            cond.clone(),
        ));

        for i in 0..MAX_NUM_OF_ARGUMENTS {
            rw_lookups.push((
                RWLookup {
                    gc: cells.gc.expression.clone() + 1.expr() + (i as u64).expr(),
                    rw_target: (RWTarget::Stack as u64).expr(),
                    rw: (RW::WRITE as u64).expr(),
                    call_index: 0.expr(),
                    address: cells.stack_size.expression.clone() - 1.expr() + (i as u64).expr(),
                    value: cells.args[i].expression.clone(),
                },
                cond.clone() * (1.expr() - cells.args_mask[i].expression.clone()),
            ));
        }

        // todo lookup bytecode table
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        // assign
        let aux_value = step.auxiliary.as_ref().ok_or_else(|| {
            error!("auxiliary is None");
            Error::Synthesis
        })?;
        cells.auxiliary.assign(region, offset, aux_value.value())?;

        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_a.assign(region, offset, op.value().value())?;

        let field_num = aux_value
            .value()
            .ok_or_else(|| {
                error!("failed to get field_num");
                Error::Synthesis
            })?
            .get_lower_128() as usize;

        // todo: We temporarily reuse cells for args here. should be abstracted as a gadget.

        // fixme: field_num may be large than MAX_NUM_OF_ARGUMENTS
        for i in 0..field_num {
            let op = rw_operations
                .0
                .get(step.gc + 1 + i)
                .ok_or(Error::Synthesis)?;
            debug_assert!(op.rw() == RW::WRITE && op.rw_target() == RWTarget::Stack);
            cells.args[i].assign(region, offset, op.value().value())?;
            cells.args_mask[i].assign(region, offset, Some(F::zero()))?;
        }

        for i in field_num..MAX_NUM_OF_ARGUMENTS {
            cells.args_mask[i].assign(region, offset, Some(F::one()))?;
        }

        Ok(())
    }
}
