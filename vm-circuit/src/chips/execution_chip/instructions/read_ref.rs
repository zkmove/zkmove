// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::{StepChipCells, WORD_CAPACITY};
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::prelude::*;
use movelang::value::DEPTH_OF_ADDRESS_PATH;
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
        // for instruction readref, there are 3 pipeline stages here:
        // 1. read reference from stack. [gc, DEPTH_OF_ADDRESS_PATH]
        // 2. read value from lobals or global. [gc+DEPTH_OF_ADDRESS_PATH, word_element_num]
        // 3. store value into stack. [gc+DEPTH_OF_ADDRESS_PATH+word_element_num, word_element_num]
        let cond = cells.conditions[Opcode::ReadRef.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cells.next_stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + depth_of_addr_path_expr.clone()
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

        for i in 0..DEPTH_OF_ADDRESS_PATH {
            lookups.rw_lookups.push((
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    0.expr(),
                    cells.ref_val[i].expression.clone(),
                ),
                cond.clone(),
            ));
        }

        let is_global = cells.auxiliary_1.expression.clone();
        for (i, item) in cells.word_b.clone().iter().enumerate().take(WORD_CAPACITY) {
            // locals read or global read
            let read = RWLookup::locals_read_ref(
                cells.gc.expression.clone() + depth_of_addr_path_expr.clone() + (i as u64).expr(),
                cells.auxiliary_2.expression.clone(), // frame_index
                cells.locals_index.expression.clone(), // index
                cells.word_a_addr_ext_0[i].expression.clone(),
                cells.word_a_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
            );
            lookups.rw_lookups.push((
                read,
                cond.clone()
                    * (1.expr() - is_global.clone())    // locals read
                    * (1.expr() - cells.word_a_mask[i].expression.clone()),
            ));
            let read = RWLookup::global_read(
                cells.gc.expression.clone() + depth_of_addr_path_expr.clone() + (i as u64).expr(),
                cells.auxiliary_2.expression.clone(), // account_address
                item.expression.clone(),
                cells.auxiliary_4.expression.clone(), //sd_index
                cells.word_a_addr_ext_0[i].expression.clone(),
                cells.word_a_addr_ext_1[i].expression.clone(),
            );
            lookups.rw_lookups.push((
                read,
                cond.clone()
                    * is_global.clone()              // global read
                    * (1.expr() - cells.word_a_mask[i].expression.clone()),
            ));

            // stack write
            let write = RWLookup::stack_push(
                cells.gc.expression.clone()
                    + depth_of_addr_path_expr.clone()
                    + word_element_num.clone()
                    + (i as u64).expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                cells.word_b_addr_ext_0[i].expression.clone(),
                cells.word_b_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
            );
            lookups.rw_lookups.push((
                write,
                cond.clone() * (1.expr() - cells.word_b_mask[i].expression.clone()),
            ));
        }

        // cells.ref_val[0] equel to frame_index(Locals) or account_address(Global)
        let mut constraint = cond.clone()
            * (cells.ref_val[0].expression.clone() - cells.auxiliary_2.expression.clone());
        constraints.push(("read_ref_eq_0", constraint));
        // cells.ref_val[1] equel to local_index(Locals) or sd_index(Global)
        constraint = cond.clone()
            * (1.expr() - is_global.clone())
            * (cells.ref_val[1].expression.clone() - cells.locals_index.expression.clone());
        constraints.push(("read_ref_eq_1", constraint));
        constraint = cond.clone()
            * is_global
            * (cells.ref_val[1].expression.clone() - cells.auxiliary_4.expression.clone());
        constraints.push(("read_ref_eq_1", constraint));
        // cells.ref_val[2] equel to word_a_addr_ext_0
        constraint = cond.clone()
            * (cells.ref_val[2].expression.clone() - cells.word_a_addr_ext_0[0].expression.clone());
        constraints.push(("read_ref_eq_2", constraint));
        // cells.ref_val[3] equel to word_a_addr_ext_1
        constraint = cond.clone()
            * (cells.ref_val[3].expression.clone() - cells.word_a_addr_ext_1[0].expression.clone());
        constraints.push(("read_ref_eq_3", constraint));

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
        Word::assign_ref_val(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc,
            DEPTH_OF_ADDRESS_PATH,
        )?;

        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;
        Word::assign_word_a(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + DEPTH_OF_ADDRESS_PATH,
            word_element_num,
        )?;
        Word::assign_word_b(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + DEPTH_OF_ADDRESS_PATH + word_element_num,
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
