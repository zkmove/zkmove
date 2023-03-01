// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::prelude::*;
use movelang::value::DEPTH_OF_ADDRESS_PATH;
use std::marker::PhantomData;

pub struct BorrowField<const MUTABLE: bool, F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<const MUTABLE: bool, F: FieldExt> Instructions<F> for BorrowField<MUTABLE, F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let opcode = if MUTABLE {
            Opcode::MutBorrowField
        } else {
            Opcode::ImmBorrowField
        };
        let cond = cells.conditions[opcode.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cells.next_stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + 2.expr() * depth_of_addr_path_expr.clone();
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

        for (i, item) in cells
            .word_b
            .clone()
            .iter()
            .enumerate()
            .take(DEPTH_OF_ADDRESS_PATH)
        {
            lookups.rw_lookups.push((
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                ),
                cond.clone() * (1.expr() - cells.word_b_mask[i].expression.clone()),
            ));

            lookups.rw_lookups.push((
                RWLookup::stack_push(
                    cells.gc.expression.clone()
                        + depth_of_addr_path_expr.clone()
                        + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    cells.word_b_addr_ext_0[i].expression.clone(),
                    cells.word_b_addr_ext_1[i].expression.clone(),
                    item.expression.clone(),
                ),
                cond.clone() * (1.expr() - cells.word_b_mask[i].expression.clone()),
            ));
        }

        // field_offset is pushed into the last element of word
        let field_offset = cells.auxiliary_2.expression.clone();
        let last_element_of_word = cells.auxiliary_4.expression.clone();
        let constraint = cond.clone() * (field_offset - last_element_of_word);
        constraints.push(("borrow_field_offset", constraint));

        LookupBytecode::lookup_bytecode(
            cells,
            opcode,
            cells.auxiliary_1.expression.clone(),
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
        Word::assign_ref_val(region, offset, step, rw_operations, cells, step.gc)?;

        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;
        Word::assign_word_b(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + DEPTH_OF_ADDRESS_PATH,
            word_element_num,
        )?;
        // the last element of word
        let last_element_word = rw_operations
            .0
            .get(step.gc + DEPTH_OF_ADDRESS_PATH + word_element_num)
            .ok_or(Error::Synthesis)?;
        cells
            .auxiliary_4
            .assign(region, offset, last_element_word.value().value())?;

        // assign the fh_idx
        let aux_value = step.auxiliary_1.as_ref().ok_or_else(|| {
            error!("auxiliary_1 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_1
            .assign(region, offset, aux_value.value())?;

        // field_offset
        let field_offset = step.auxiliary_2.as_ref().ok_or_else(|| {
            error!("auxiliary_2 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_2
            .assign(region, offset, field_offset.value())?;

        Ok(())
    }
}
