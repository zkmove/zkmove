// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{FlattenedValue, LookupBytecode};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{
    rw_table::RWLookup, rw_table::RWTarget, LookupsWithCondition,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::{StepChipCells, MAX_NUM_OF_FLATTENED_STRUCT_FIELDS};
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
        lookups: &mut LookupsWithCondition<F>,
    ) {
        //Pack
        let cond = cells.conditions[Opcode::Pack.index()].expression.clone();
        let field_num = cells.auxiliary_1.expression.clone();
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - field_num.clone()
            + 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let flattened_field_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + field_num.clone()
            + flattened_field_num.clone();
        let module_index =
            cells.module_index.expression.clone() - cells.next_module_index.expression.clone();
        let func_index =
            cells.function_index.expression.clone() - cells.next_function_index.expression.clone();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("frame index", cond.clone() * frame_index_expr),
            ("gc", cond.clone() * gc_expr),
            ("module index", cond.clone() * module_index),
            ("function index", cond.clone() * func_index),
        ]);

        for i in 0..MAX_NUM_OF_FLATTENED_STRUCT_FIELDS {
            lookups.rw_lookups.push((
                RWLookup {
                    gc: cells.gc.expression.clone() + (i as u64).expr(),
                    rw_target: (RWTarget::Stack as u64).expr(),
                    rw: (RW::READ as u64).expr(),
                    frame_index: 0.expr(),
                    address: cells.stack_size.expression.clone() - field_num.clone()
                        + (i as u64).expr(),
                    nested_address_0: 0.expr(),
                    nested_address_1: 0.expr(),
                    value: cells.args_or_fields[i].expression.clone(),
                    sd_index: 0.expr(),
                },
                cond.clone() * (1.expr() - cells.args_or_fields_mask[i].expression.clone()),
            ));
        }
        for i in 0..MAX_NUM_OF_FLATTENED_STRUCT_FIELDS {
            lookups.rw_lookups.push((
                RWLookup::stack_push(
                    cells.gc.expression.clone() + field_num.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone() - field_num.clone(),
                    cells.flattened_nested_addr_0[i].expression.clone(),
                    cells.flattened_nested_addr_1[i].expression.clone(),
                    cells.flattened[i].expression.clone(),
                ),
                cond.clone() * (1.expr() - cells.flattened_mask[i].expression.clone()),
            ));
        }

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Pack,
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
        let aux_value = step.auxiliary_1.as_ref().ok_or_else(|| {
            error!("auxiliary_1 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_1
            .assign(region, offset, aux_value.value())?;

        let field_num = aux_value
            .value()
            .ok_or_else(|| {
                error!("failed to get field_num");
                Error::Synthesis
            })?
            .get_lower_128() as usize;

        // fixme: field_num may be large than MAX_NUM_OF_FLATTENED_STRUCT_FIELDS
        for i in 0..field_num {
            let op = rw_operations.0.get(step.gc + i).ok_or(Error::Synthesis)?;
            debug_assert!(op.rw() == RW::READ && op.rw_target() == RWTarget::Stack);
            cells.args_or_fields[i].assign(region, offset, op.value().value())?;
            cells.args_or_fields_mask[i].assign(region, offset, Some(F::zero()))?;
        }

        for i in field_num..MAX_NUM_OF_FLATTENED_STRUCT_FIELDS {
            cells.args_or_fields_mask[i].assign(region, offset, Some(F::one()))?;
        }

        let flattened_field_num =
            FlattenedValue::get_flattened_field_num(region, offset, step, cells)?;
        FlattenedValue::assign_flattened_a(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + field_num,
            flattened_field_num,
        )?;

        let sd_idx = step.auxiliary_2.as_ref().ok_or_else(|| {
            error!("auxiliary_2 is None");
            Error::Synthesis
        })?;
        cells.auxiliary_2.assign(region, offset, sd_idx.value())?;

        Ok(())
    }
}
