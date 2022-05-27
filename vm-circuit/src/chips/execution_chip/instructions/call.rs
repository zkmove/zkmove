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

pub struct Call<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for Call<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        _bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::Call.index()].expression.clone();
        let arg_num = cells.auxiliary.expression.clone();
        // next pc is always 0
        let pc_expr = cells.next_pc.expression.clone();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - arg_num.clone();
        // call index increase 1
        let call_index_expr = cells.call_index.expression.clone()
            - cells.next_call_index.expression.clone()
            + 1.expr();
        // each argument has 2 rw operations
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + arg_num.clone() * 2.expr();
        constraints.append(&mut vec![
            ("Call pc", cond.clone() * pc_expr),
            ("Call stack_size", cond.clone() * stack_size_expr),
            ("Call call_index", cond.clone() * call_index_expr),
            ("Call gc", cond.clone() * gc_expr),
        ]);

        for i in 0..MAX_NUM_OF_ARGUMENTS {
            let (read, write) = RWLookup::locals_store(
                cells.gc.expression.clone() + (i as u64 * 2).expr(),
                cells.call_index.expression.clone() + 1.expr(),
                arg_num.clone() - (i as u64 + 1).expr(),
                cells.stack_size.expression.clone() - (i as u64).expr(),
                cells.args[i].expression.clone(),
            );

            rw_lookups.push((
                read,
                cond.clone() * (1.expr() - cells.args_mask[i].expression.clone()),
            ));
            rw_lookups.push((
                write,
                cond.clone() * (1.expr() - cells.args_mask[i].expression.clone()),
            ));
        }

        // todo: lookup Call(index: FunctionHandleIndex) in bytecode table. how to constrain index?
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        // assign arg_num
        let aux_value = step.auxiliary.as_ref().ok_or_else(|| {
            error!("auxiliary is None");
            Error::Synthesis
        })?;
        cells.auxiliary.assign(region, offset, aux_value.value())?;

        let arg_num = aux_value
            .value()
            .ok_or_else(|| {
                error!("failed to get arg_num");
                Error::Synthesis
            })?
            .get_lower_128() as usize;

        for i in 0..arg_num {
            let op = rw_operations
                .0
                .get(step.gc + i * 2)
                .ok_or(Error::Synthesis)?;
            debug_assert!(op.rw() == RW::READ && op.rw_target() == RWTarget::Stack);
            cells.args[i].assign(region, offset, op.value().value())?;
            cells.args_mask[i].assign(region, offset, Some(F::zero()))?;
        }

        for i in arg_num..MAX_NUM_OF_ARGUMENTS {
            cells.args_mask[i].assign(region, offset, Some(F::one()))?;
        }

        Ok(())
    }
}
