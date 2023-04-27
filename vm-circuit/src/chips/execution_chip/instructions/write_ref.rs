// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{
    LookupBytecode, RefVal, Word, WordA, WordB,
};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::WORD_CAPACITY;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use movelang::value::DEPTH_OF_ADDRESS_PATH;

#[derive(Clone, Debug)]
pub struct WriteRef<F: FieldExt> {
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,
    word_b: Vec<Cell<F>>,
    word_b_mask: Vec<Cell<F>>,
    word_b_addr_ext_0: Vec<Cell<F>>,
    word_b_addr_ext_1: Vec<Cell<F>>,
    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for WriteRef<F> {
    const NAME: &'static str = "WRITEREF";

    const OPCODE: Opcode = Opcode::WriteRef;
    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        // for instruction readref, there are 3 pipeline stages here:
        // 1. read reference from stack. [gc, DEPTH_OF_ADDRESS_PATH]
        // 2. read value into stack. [gc+DEPTH_OF_ADDRESS_PATH, word_element_num]
        // 3. write value to lobals or global. [gc+DEPTH_OF_ADDRESS_PATH+word_element_num, word_element_num]
        let cond = cells.conditions[Opcode::WriteRef.index()]
            .expression
            .clone();

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 2.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + depth_of_addr_path_expr.clone()
            + 2.expr() * word_element_num.clone();
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();
        cb.add_constraints(vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("frame index", cond.clone() * frame_index_expr),
            ("gc", cond.clone() * gc_expr),
            ("module index", cond.clone() * module_index),
            ("function index", cond.clone() * func_index),
        ]);

        for (i, item) in self.ref_val.iter().enumerate().take(DEPTH_OF_ADDRESS_PATH) {
            // for i in 0..DEPTH_OF_ADDRESS_PATH {
            lookups.rw_lookups.push((
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                ),
                cond.clone(),
            ));
        }

        let is_global = cells.auxiliary_1.expression.clone();
        for (i, item) in self.word_b.iter().enumerate().take(WORD_CAPACITY) {
            // stack read
            let read = RWLookup::stack_pop(
                cells.gc.expression.clone() + depth_of_addr_path_expr.clone() + (i as u64).expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                self.word_a_addr_ext_0[i].expression.clone(),
                self.word_a_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
            );
            lookups.rw_lookups.push((
                read,
                cond.clone() * (1.expr() - self.word_a_mask[i].expression.clone()),
            ));

            // locals write or global write
            let write = RWLookup::locals_write_ref(
                cells.gc.expression.clone()
                    + depth_of_addr_path_expr.clone()
                    + word_element_num.clone()
                    + (i as u64).expr(),
                cells.auxiliary_2.expression.clone(),
                cells.locals_index.expression.clone(),
                self.word_b_addr_ext_0[i].expression.clone(),
                self.word_b_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
            );
            lookups.rw_lookups.push((
                write,
                cond.clone()
                    * (1.expr() - is_global.clone())
                    * (1.expr() - self.word_b_mask[i].expression.clone()),
            ));

            let write = RWLookup::global_write(
                cells.gc.expression.clone()
                    + depth_of_addr_path_expr.clone()
                    + word_element_num.clone()
                    + (i as u64).expr(),
                cells.auxiliary_2.expression.clone(), //address
                self.word_b[i].expression.clone(),
                cells.auxiliary_4.expression.clone(), //sd_index
                self.word_b_addr_ext_0[i].expression.clone(),
                self.word_b_addr_ext_1[i].expression.clone(),
            );
            lookups.rw_lookups.push((
                write,
                cond.clone()
                    * is_global.clone()
                    * (1.expr() - self.word_b_mask[i].expression.clone()),
            ));
        }

        // cells.ref_val[0] equel to frame_index(Locals) or account_address(Global)
        let mut constraint = cond.clone()
            * (self.ref_val[0].expression.clone() - cells.auxiliary_2.expression.clone());
        cb.add_constraint("write_ref_eq_0", constraint);
        // cells.ref_val[1] equel to local_index(Locals) or sd_index(Global)
        constraint = cond.clone()
            * (1.expr() - is_global.clone())
            * (self.ref_val[1].expression.clone() - cells.locals_index.expression.clone());
        cb.add_constraint("write_ref_eq_1", constraint);
        constraint = cond.clone()
            * is_global
            * (self.ref_val[1].expression.clone() - cells.auxiliary_4.expression.clone());
        cb.add_constraint("write_ref_eq_1", constraint);
        // cells.ref_val[2] equel to addr_ext_0
        constraint = cond.clone()
            * (self.ref_val[2].expression.clone() - self.word_b_addr_ext_0[0].expression.clone());
        cb.add_constraint("write_ref_eq_2", constraint);
        // cells.ref_val[3] equel to addr_ext_1
        constraint = cond.clone()
            * (self.ref_val[3].expression.clone() - self.word_b_addr_ext_1[0].expression.clone());
        cb.add_constraint("write_ref_eq_3", constraint);

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::WriteRef,
            0.expr(),
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
        let ref_val = RefVal {
            ref_val: self.ref_val.clone(),
            ref_val_mask: self.ref_val_mask.clone(),
        };
        Word::assign_ref_val(
            region,
            offset,
            step,
            rw_operations,
            &ref_val,
            step.gc,
            DEPTH_OF_ADDRESS_PATH,
        )?;

        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;
        let word_a = WordA {
            word_a: self.word_a.clone(),
            word_a_mask: self.word_a_mask.clone(),
            word_a_addr_ext_0: self.word_a_addr_ext_0.clone(),
            word_a_addr_ext_1: self.word_a_addr_ext_1.clone(),
        };
        Word::assign_word_a(
            region,
            offset,
            step,
            rw_operations,
            &word_a,
            step.gc + DEPTH_OF_ADDRESS_PATH,
            word_element_num,
        )?;

        let word_b = WordB {
            word_b: self.word_b.clone(),
            word_b_mask: self.word_b_mask.clone(),
            word_b_addr_ext_0: self.word_b_addr_ext_0.clone(),
            word_b_addr_ext_1: self.word_b_addr_ext_1.clone(),
        };
        Word::assign_word_b(
            region,
            offset,
            step,
            rw_operations,
            &word_b,
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

        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);

        Self {
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            word_a_addr_ext_1,
            word_b,
            word_b_mask,
            word_b_addr_ext_0,
            word_b_addr_ext_1,
            ref_val,
            ref_val_mask,
        }
    }
}
