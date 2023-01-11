// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::LookupBytecode;
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{
    rw_table::RWLookup, rw_table::RWTarget, LookupsWithCondition,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::{StepChipCells, NUM_OF_BYTES};
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
        lookups: &mut LookupsWithCondition<F>,
    ) {
        //Unpack
        let cond = cells.conditions[Opcode::Unpack.index()].expression.clone();
        let field_num = cells.auxiliary_1.expression.clone();
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            + field_num.clone()
            - 1.expr();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr =
            cells.gc.expression.clone() - cells.next_gc.expression.clone() + field_num + 1.expr();
        let module_index =
            cells.module_index.expression.clone() - cells.next_module_index.expression.clone();
        let func_index =
            cells.function_index.expression.clone() - cells.next_function_index.expression.clone();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("call index", cond.clone() * call_index_expr),
            ("gc", cond.clone() * gc_expr),
            ("module index", cond.clone() * module_index),
            ("function index", cond.clone() * func_index),
        ]);

        lookups.rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                cells.value_a.expression.clone(),
            ),
            cond.clone(),
        ));

        for i in 0..NUM_OF_BYTES {
            lookups.rw_lookups.push((
                RWLookup {
                    gc: cells.gc.expression.clone() + 1.expr() + (i as u64).expr(),
                    rw_target: (RWTarget::Stack as u64).expr(),
                    rw: (RW::WRITE as u64).expr(),
                    call_index: 0.expr(),
                    address: cells.stack_size.expression.clone() - 1.expr() + (i as u64).expr(),
                    value: cells.bytes[i].expression.clone(),
                    sd_index: 0.expr(),
                },
                cond.clone() * (1.expr() - cells.bytes_mask[i].expression.clone()),
            ));
        }

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Unpack,
            cells.auxiliary_2.expression.clone(),
            &mut lookups.bytecode_lookups,
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
        // assign
        let aux_value = step.auxiliary_1.as_ref().ok_or_else(|| {
            error!("auxiliary_1 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_1
            .assign(region, offset, aux_value.value())?;

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

        // fixme: field_num may be large than NUM_OF_BYTES
        for i in 0..field_num {
            let op = rw_operations
                .0
                .get(step.gc + 1 + i)
                .ok_or(Error::Synthesis)?;
            debug_assert!(op.rw() == RW::WRITE && op.rw_target() == RWTarget::Stack);
            cells.bytes[i].assign(region, offset, op.value().value())?;
            cells.bytes_mask[i].assign(region, offset, Some(F::zero()))?;
        }

        for i in field_num..NUM_OF_BYTES {
            cells.bytes_mask[i].assign(region, offset, Some(F::one()))?;
        }

        let sd_idx = step.auxiliary_2.as_ref().ok_or_else(|| {
            error!("auxiliary_2 is None");
            Error::Synthesis
        })?;
        cells.auxiliary_2.assign(region, offset, sd_idx.value())?;

        Ok(())
    }
}
