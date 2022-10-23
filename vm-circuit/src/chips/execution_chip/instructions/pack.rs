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

pub struct Pack<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for Pack<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        _bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        //Pack
        let cond = cells.conditions[Opcode::Pack.index()].expression.clone();
        let field_num = cells.auxiliary.expression.clone();
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - field_num.clone()
            + 1.expr();
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

        for i in 0..MAX_NUM_OF_ARGUMENTS {
            rw_lookups.push((
                RWLookup {
                    gc: cells.gc.expression.clone() + (i as u64).expr(),
                    rw_target: (RWTarget::Stack as u64).expr(),
                    rw: (RW::READ as u64).expr(),
                    call_index: 0.expr(),
                    address: cells.stack_size.expression.clone() - field_num.clone()
                        + (i as u64).expr(),
                    value: cells.args[i].expression.clone(),
                },
                cond.clone() * (1.expr() - cells.args_mask[i].expression.clone()),
            ));
        }
        rw_lookups.push((
            RWLookup::stack_push(
                cells.gc.expression.clone() + field_num.clone(),
                cells.stack_size.expression.clone() - field_num.clone(),
                cells.value_c.expression.clone(),
            ),
            cond.clone(),
        ));

        // todo lookup bytecode table
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let aux_value = step.auxiliary.as_ref().ok_or_else(|| {
            error!("auxiliary is None");
            Error::Synthesis
        })?;
        cells.auxiliary.assign(region, offset, aux_value.value())?;

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
            let op = rw_operations.0.get(step.gc + i).ok_or(Error::Synthesis)?;
            debug_assert!(op.rw() == RW::READ && op.rw_target() == RWTarget::Stack);
            cells.args[i].assign(region, offset, op.value().value())?;
            cells.args_mask[i].assign(region, offset, Some(F::zero()))?;
        }

        for i in field_num..MAX_NUM_OF_ARGUMENTS {
            cells.args_mask[i].assign(region, offset, Some(F::one()))?;
        }

        let op = rw_operations
            .0
            .get(step.gc + field_num)
            .ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        cells.value_c.assign(region, offset, op.value().value())?;

        Ok(())
    }
}
