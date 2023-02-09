// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{FlattenedValue, LookupBytecode};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::rw_table::RWTarget;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::{StepChipCells, MAX_NUM_OF_FLATTENED_STRUCT_FIELDS};
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct MoveLoc<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for MoveLoc<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.conditions[Opcode::MoveLoc.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            + 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let flattened_field_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + 2.expr() * flattened_field_num.clone()
            + 1.expr();
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
            let (read, write_stack) = RWLookup::locals_move_without_flash(
                cells.gc.expression.clone() + (i as u64).expr(),
                cells.frame_index.expression.clone(),
                cells.locals_index.expression.clone(),
                cells.stack_size.expression.clone(),
                cells.flattened_nested_addr_0[i].expression.clone(),
                cells.flattened_nested_addr_1[i].expression.clone(),
                cells.flattened[i].expression.clone(),
                flattened_field_num.clone(), // flattened_field_num
            );

            lookups.rw_lookups.push((
                read,
                cond.clone() * (1.expr() - cells.flattened_mask[i].expression.clone()),
            ));
            lookups.rw_lookups.push((
                write_stack,
                cond.clone() * (1.expr() - cells.flattened_mask[i].expression.clone()),
            ));
        }
        // do flash, happened between read and write_stack
        let write_locals = RWLookup {
            gc: cells.gc.expression.clone() + flattened_field_num.clone(),
            rw_target: (RWTarget::Locals as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            frame_index: cells.frame_index.expression.clone(),
            address: cells.locals_index.expression.clone(),
            nested_address_0: 0.expr(),
            nested_address_1: 0.expr(),
            value: 0.expr(), // todo: is it ok to use 0 for Value::Invalid?
            sd_index: 0.expr(),
        };
        lookups.rw_lookups.push((write_locals, cond.clone()));

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::MoveLoc,
            cells.locals_index.expression.clone(),
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
        let flattened_field_num =
            FlattenedValue::get_flattened_field_num(region, offset, step, cells)?;
        FlattenedValue::assign_flattened_a(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc,
            flattened_field_num,
        )?;

        Ok(())
    }
}
