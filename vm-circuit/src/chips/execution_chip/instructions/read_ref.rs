// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{FlattenedValue, LookupBytecode};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::{StepChipCells, MAX_NUM_OF_FLATTENED_STRUCT_FIELDS};
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::prelude::*;
use std::marker::PhantomData;

pub struct ReadRef<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for ReadRef<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.conditions[Opcode::ReadRef.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cells.next_stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let flattened_field_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + 1.expr()
            + 2.expr() * flattened_field_num.clone();
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

        lookups.rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                cells.value_a.expression.clone(),
            ),
            cond.clone(),
        ));

        let is_locals = 1.expr() - cells.auxiliary_1.expression.clone();

        for i in 0..MAX_NUM_OF_FLATTENED_STRUCT_FIELDS {
            let read = RWLookup::locals_read_ref(
                cells.gc.expression.clone() + 1.expr() + (i as u64).expr(),
                cells.auxiliary_2.expression.clone(),
                cells.locals_index.expression.clone(),
                cells.flattened_nested_addr_0[i].expression.clone(),
                cells.flattened_nested_addr_1[i].expression.clone(),
                cells.flattened[i].expression.clone(),
            );

            lookups.rw_lookups.push((
                read,
                cond.clone()
                    * is_locals.clone()
                    * (1.expr() - cells.flattened_mask[i].expression.clone()),
            ));
        }

        let is_global = cells.auxiliary_1.expression.clone();
        let read = RWLookup::global_read(
            cells.gc.expression.clone() + 1.expr(),
            cells.auxiliary_2.expression.clone(), //address
            cells.value_b.expression.clone(),
            cells.auxiliary_4.expression.clone(), //sd_index
            0.expr(),
            0.expr(),
        );
        lookups.rw_lookups.push((read, cond.clone() * is_global));

        for i in 0..MAX_NUM_OF_FLATTENED_STRUCT_FIELDS {
            let write = RWLookup::stack_push(
                cells.gc.expression.clone()
                    + 1.expr()
                    + flattened_field_num.clone()
                    + (i as u64).expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                cells.args_or_fields_nested_addr_0[i].expression.clone(),
                cells.args_or_fields_nested_addr_1[i].expression.clone(),
                cells.args_or_fields[i].expression.clone(),
            );

            lookups.rw_lookups.push((
                write,
                cond.clone() * (1.expr() - cells.args_or_fields_mask[i].expression.clone()),
            ));
        }

        // todo: constrain cells.args_or_fields == cells.flattened

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::ReadRef,
            0.expr(),
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
        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_a.assign(region, offset, op.value().value())?;
        // let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        // debug_assert!(op.rw() == RW::READ);
        // cells.value_b.assign(region, offset, op.value().value())?;
        // let op = rw_operations.0.get(step.gc + 2).ok_or(Error::Synthesis)?;
        // debug_assert!(op.rw() == RW::WRITE);
        // cells.value_c.assign(region, offset, op.value().value())?;

        let flattened_field_num =
            FlattenedValue::get_flattened_field_num(region, offset, step, cells)?;
        FlattenedValue::assign_flattened_a(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + 1,
            flattened_field_num,
        )?;
        FlattenedValue::assign_flattened_b(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + 1 + flattened_field_num,
            flattened_field_num,
        )?;

        let is_global = step.auxiliary_1.as_ref().ok_or_else(|| {
            error!("auxiliary_1 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_1
            .assign(region, offset, is_global.value())?;

        if is_global.value() == Some(F::zero()) {
            // assign the frame_index of the frame we refer to
            let aux_value = step.auxiliary_2.as_ref().ok_or_else(|| {
                error!("auxiliary_2 is None");
                Error::Synthesis
            })?;
            cells
                .auxiliary_2
                .assign(region, offset, aux_value.value())?;
        } else {
            // assign the account address to auxiliary_2
            let address = step.auxiliary_2.as_ref().ok_or_else(|| {
                error!("auxiliary_2 is None");
                Error::Synthesis
            })?;
            cells.auxiliary_2.assign(region, offset, address.value())?;

            // assign the sd_index to auxiliary_4
            let sd_index = step.auxiliary_4.as_ref().ok_or_else(|| {
                error!("auxiliary_4 is None");
                Error::Synthesis
            })?;
            cells.auxiliary_4.assign(region, offset, sd_index.value())?;
        }
        Ok(())
    }
}
