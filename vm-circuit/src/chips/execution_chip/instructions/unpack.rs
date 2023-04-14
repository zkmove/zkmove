// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{
    rw_table::RWLookup, rw_table::RWTarget, LookupsWithCondition,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::WORD_CAPACITY;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::prelude::*;
use std::marker::PhantomData;

pub struct Unpack<F: FieldExt> {
    _word_a_mask: [Cell<F>; WORD_CAPACITY],
    _word_a_addr_ext_0: [Cell<F>; WORD_CAPACITY],
    _word_a_addr_ext_1: [Cell<F>; WORD_CAPACITY],
    _word_b: [Cell<F>; WORD_CAPACITY],
    _word_b_mask: [Cell<F>; WORD_CAPACITY],
    _word_b_addr_ext_0: [Cell<F>; WORD_CAPACITY],
    _word_b_addr_ext_1: [Cell<F>; WORD_CAPACITY],
    _word_address: [Cell<F>; WORD_CAPACITY],
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
            + field_num
            - 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + word_element_num.clone() * 2.expr();
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

        // word_a used for struct and word_b used for unpacked fields.
        for (i, item) in cells.word_b.clone().iter().enumerate().take(WORD_CAPACITY) {
            lookups.rw_lookups.push((
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    cells.word_a_addr_ext_0[i].expression.clone(),
                    cells.word_a_addr_ext_1[i].expression.clone(),
                    item.expression.clone(),
                ),
                cond.clone() * (1.expr() - cells.word_a_mask[i].expression.clone()),
            ));

            lookups.rw_lookups.push((
                RWLookup {
                    gc: cells.gc.expression.clone() + word_element_num.clone() + (i as u64).expr(),
                    rw_target: (RWTarget::Stack as u64).expr(),
                    rw: (RW::WRITE as u64).expr(),
                    frame_index: 0.expr(),
                    address: cells.word_address[i].expression.clone(),
                    address_ext_0: cells.word_b_addr_ext_0[i].expression.clone(),
                    address_ext_1: cells.word_b_addr_ext_1[i].expression.clone(),
                    value: item.expression.clone(),
                    sd_index: 0.expr(),
                },
                cond.clone() * (1.expr() - cells.word_b_mask[i].expression.clone()),
            ));
        }

        //  word_a.address_ext_0 equal to word_b.address
        //  word_a.address_ext_1 equal to word_b.address_ext_0
        for i in 0..WORD_CAPACITY {
            let constraint = cond.clone()
                * cells.word_a_mask[i].expression.clone()
                * (cells.word_address[i].expression.clone()
                    - cells.word_a_addr_ext_0[i].expression.clone());
            constraints.push(("unpack_address_eq", constraint));
            let constraint = cond.clone()
                * cells.word_a_mask[i].expression.clone()
                * (cells.word_b_addr_ext_0[i].expression.clone()
                    - cells.word_a_addr_ext_1[i].expression.clone());
            constraints.push(("unpack_address_ext_0_eq", constraint));
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
        let field_num = step.auxiliary_1.as_ref().ok_or_else(|| {
            error!("auxiliary_1 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_1
            .assign(region, offset, field_num.value())?;

        // assign
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
        Word::assign_word_b_with_address(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + word_element_num,
            word_element_num,
        )?;

        let sd_idx = step.auxiliary_2.as_ref().ok_or_else(|| {
            error!("auxiliary_2 is None");
            Error::Synthesis
        })?;
        cells.auxiliary_2.assign(region, offset, sd_idx.value())?;

        Ok(())
    }
}
