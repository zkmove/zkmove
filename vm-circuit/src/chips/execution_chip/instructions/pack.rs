// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{
    rw_table::RWLookup, rw_table::RWTarget, LookupsWithCondition,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::WORD_CAPACITY;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;

#[derive(Clone, Debug)]
pub struct Pack<const GENERIC: bool, F: FieldExt> {
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,
    word_b: Vec<Cell<F>>,
    word_b_mask: Vec<Cell<F>>,
    word_b_addr_ext_0: Vec<Cell<F>>,
    word_b_addr_ext_1: Vec<Cell<F>>,
    word_address: Vec<Cell<F>>,
}

impl<const GENERIC: bool, F: FieldExt> InstructionGadget<F> for Pack<GENERIC, F> {
    const NAME: &'static str = if GENERIC { "PACK_GENERIC" } else { "PACK" };

    const OPCODE: Opcode = if GENERIC {
        Opcode::PackGeneric
    } else {
        Opcode::Pack
    };

    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        //Pack
        let cond = cells.opcode_selector([Self::OPCODE]);

        let field_num = cells.auxiliary_1.expression.clone();
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - field_num.clone()
            + 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_a_element_num = cells.auxiliary_3.expression.clone();
        let word_b_element_num = word_a_element_num.clone() - 1.expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + word_b_element_num.clone()
            + word_a_element_num;
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();
        cb.add_constraints(vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("frame index", cond.clone() * frame_index_expr),
            ("pack gc", cond.clone() * gc_expr),
            ("module index", cond.clone() * module_index),
            ("function index", cond.clone() * func_index),
        ]);

        // read values from stack, write back the packed struct
        // word_a[0] is the header. To make the constraint simple, we have already
        // assigned the word_b[0] to be empty, now we just skip 'i=0'.
        for (i, item) in self.word_b.iter().enumerate().take(WORD_CAPACITY).skip(1) {
            lookups.rw_lookups.push((
                "pack(stack pop)",
                RWLookup {
                    gc: cells.gc.expression.clone() + ((i - 1) as u64).expr(),
                    rw_target: (RWTarget::Stack as u64).expr(),
                    rw: (RW::READ as u64).expr(),
                    frame_index: 0.expr(),
                    address: self.word_address[i].expression.clone(),
                    address_ext_0: self.word_b_addr_ext_0[i].expression.clone(),
                    address_ext_1: self.word_b_addr_ext_1[i].expression.clone(),
                    value: item.expression.clone(),
                    sd_index: 0.expr(),
                },
                cond.clone() * (1.expr() - self.word_b_mask[i].expression.clone()),
            ));

            lookups.rw_lookups.push((
                "pack(stack push)",
                RWLookup::stack_push(
                    cells.gc.expression.clone() + word_b_element_num.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone() - field_num.clone(),
                    self.word_a_addr_ext_0[i].expression.clone(),
                    self.word_a_addr_ext_1[i].expression.clone(),
                    item.expression.clone(),
                ),
                cond.clone() * (1.expr() - self.word_a_mask[i].expression.clone()),
            ));
        }

        lookups.rw_lookups.push((
            "pack(write struct header)",
            RWLookup::stack_push(
                cells.gc.expression.clone() + word_b_element_num,
                cells.stack_size.expression.clone() - field_num,
                self.word_a_addr_ext_0[0].expression.clone(),
                self.word_a_addr_ext_1[0].expression.clone(),
                self.word_a[0].expression.clone(),
            ),
            cond.clone() * (1.expr() - self.word_a_mask[0].expression.clone()),
        ));

        // word_b.address is equal to word_a.address_ext_0
        // word_b.address_ext_0 is equal to word_a.address_ext_1
        for i in 1..WORD_CAPACITY {
            let constraint = cond.clone()
                * self.word_a_mask[i].expression.clone()
                * (self.word_address[i].expression.clone()
                    - self.word_a_addr_ext_0[i].expression.clone());
            cb.add_constraint("pack_address_eq", constraint);
            let constraint = cond.clone()
                * self.word_a_mask[i].expression.clone()
                * (self.word_b_addr_ext_0[i].expression.clone()
                    - self.word_a_addr_ext_1[i].expression.clone());
            cb.add_constraint("pack_address_ext_0_eq", constraint);
        }

        LookupBytecode::lookup_bytecode(
            cells,
            Self::OPCODE,
            cells.auxiliary_2.expression.clone(),
            &mut lookups.bytecode_lookups,
            cond,
        );
    }

    fn assign(
        &self,
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

        let word_a_element_num = Word::get_word_element_num(region, offset, step, cells)?;
        let word_b_element_num = word_a_element_num - 1;

        let word_b = Word {
            word: self.word_b.clone(),
            word_mask: self.word_b_mask.clone(),
            word_addr_ext_0: self.word_b_addr_ext_0.clone(),
            word_addr_ext_1: self.word_b_addr_ext_1.clone(),
        };
        Word::assign_word_with_address(
            region,
            offset,
            rw_operations,
            &word_b,
            &self.word_address,
            step.gc,
            word_b_element_num,
        )?;

        let word_a = Word {
            word: self.word_a.clone(),
            word_mask: self.word_a_mask.clone(),
            word_addr_ext_0: self.word_a_addr_ext_0.clone(),
            word_addr_ext_1: self.word_a_addr_ext_1.clone(),
        };
        Word::assign_word(
            region,
            offset,
            step,
            rw_operations,
            &word_a,
            step.gc + word_b_element_num,
            word_a_element_num,
        )?;

        let sd_idx = step.auxiliary_2.as_ref().ok_or_else(|| {
            error!("auxiliary_2 is None");
            Error::Synthesis
        })?;
        cells.auxiliary_2.assign(region, offset, sd_idx.value())?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let word_a = cb.alloc_n_cells(WORD_CAPACITY);
        let word_a_mask = cb.alloc_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);
        let word_b = cb.alloc_n_cells(WORD_CAPACITY);
        let word_b_mask = cb.alloc_n_cells(WORD_CAPACITY);
        let word_b_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let word_b_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);
        let word_address = cb.alloc_n_cells(WORD_CAPACITY);

        Self {
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            word_a_addr_ext_1,
            word_b,
            word_b_mask,
            word_b_addr_ext_0,
            word_b_addr_ext_1,
            word_address,
        }
    }
}
