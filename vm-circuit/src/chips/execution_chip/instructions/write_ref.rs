// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::{StepChipCells, WORD_CAPACITY};
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::prelude::*;
use std::marker::PhantomData;

pub struct WriteRef<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for WriteRef<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.conditions[Opcode::WriteRef.index()]
            .expression
            .clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - 2.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + 1.expr()
            + 2.expr() * word_element_num.clone();
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

        for i in 0..WORD_CAPACITY {
            let write = RWLookup::stack_pop(
                cells.gc.expression.clone() + 1.expr() + (i as u64).expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                cells.word_a_addr_ext_0[i].expression.clone(),
                cells.word_a_addr_ext_1[i].expression.clone(),
                cells.word_a[i].expression.clone(),
            );

            lookups.rw_lookups.push((
                write,
                cond.clone() * (1.expr() - cells.word_a_mask[i].expression.clone()),
            ));
        }
        let is_locals = 1.expr() - cells.auxiliary_1.expression.clone();

        for i in 0..WORD_CAPACITY {
            let read = RWLookup::locals_write_ref(
                cells.gc.expression.clone()
                    + 1.expr()
                    + word_element_num.clone()
                    + (i as u64).expr(),
                cells.auxiliary_2.expression.clone(),
                cells.locals_index.expression.clone(),
                cells.word_b_addr_ext_0[i].expression.clone(),
                cells.word_b_addr_ext_1[i].expression.clone(),
                cells.word_b[i].expression.clone(),
            );

            lookups.rw_lookups.push((
                read,
                cond.clone()
                    * is_locals.clone()
                    * (1.expr() - cells.word_b_mask[i].expression.clone()),
            ));
        }

        let is_global = cells.auxiliary_1.expression.clone();
        for i in 0..WORD_CAPACITY {
            let read = RWLookup::global_write(
                cells.gc.expression.clone()
                    + 1.expr()
                    + word_element_num.clone()
                    + (i as u64).expr(),
                cells.auxiliary_2.expression.clone(), //address
                cells.word_b[i].expression.clone(),
                cells.auxiliary_4.expression.clone(), //sd_index
                cells.word_b_addr_ext_0[i].expression.clone(),
                cells.word_b_addr_ext_1[i].expression.clone(),
            );
            lookups.rw_lookups.push((
                read,
                cond.clone()
                    * is_global.clone()
                    * (1.expr() - cells.word_b_mask[i].expression.clone()),
            ));
        }

        // todo: constrain cells.word_b == cells.word_a

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::WriteRef,
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

        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;
        Word::assign_word_a(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + 1,
            word_element_num,
        )?;
        Word::assign_word_b(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + 1 + word_element_num,
            word_element_num,
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
