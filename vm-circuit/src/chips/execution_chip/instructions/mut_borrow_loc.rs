// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::rw_table::RWTarget;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::{StepChipCells, WORD_CAPACITY};
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct MutBorrowLoc<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for MutBorrowLoc<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.conditions[Opcode::MutBorrowLoc.index()]
            .expression
            .clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            + 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + word_element_num.clone()
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

        for i in 0..WORD_CAPACITY {
            let read = RWLookup::locals_ref(
                cells.gc.expression.clone() + (i as u64).expr(),
                cells.frame_index.expression.clone(),
                cells.locals_index.expression.clone(),
                cells.word_a_addr_ext_0[i].expression.clone(),
                cells.word_a_addr_ext_1[i].expression.clone(),
                cells.word_a[i].expression.clone(),
            );

            lookups.rw_lookups.push((
                read,
                cond.clone() * (1.expr() - cells.word_a_mask[i].expression.clone()),
            ));
        }

        let write = RWLookup {
            gc: cells.gc.expression.clone() + word_element_num,
            rw_target: (RWTarget::Stack as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            frame_index: 0.expr(),
            address: cells.stack_size.expression.clone(),
            address_ext_0: 0.expr(),
            address_ext_1: 0.expr(),
            value: cells.value_c.expression.clone(),
            sd_index: 0.expr(),
        };
        lookups.rw_lookups.push((write, cond.clone()));

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::MutBorrowLoc,
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
        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;
        Word::assign_word_a(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc,
            word_element_num,
        )?;
        let op = rw_operations
            .0
            .get(step.gc + word_element_num)
            .ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        cells.value_c.assign(region, offset, op.value().value())?;
        Ok(())
    }
}
