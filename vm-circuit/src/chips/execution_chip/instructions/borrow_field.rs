// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, RefVal, Word, WordB};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::WORD_CAPACITY;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use movelang::value::DEPTH_OF_ADDRESS_PATH;

#[derive(Clone, Debug)]
pub struct BorrowField<const MUTABLE: bool, F: FieldExt> {
    word_b: Vec<Cell<F>>,
    word_b_mask: Vec<Cell<F>>,
    word_b_addr_ext_0: Vec<Cell<F>>,
    word_b_addr_ext_1: Vec<Cell<F>>,
    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,
}

impl<const MUTABLE: bool, F: FieldExt> InstructionGadget<F> for BorrowField<MUTABLE, F> {
    const NAME: &'static str = "BORROWFIELD";

    const OPCODE: Opcode = if MUTABLE {
        Opcode::MutBorrowField
    } else {
        Opcode::ImmBorrowField
    };

    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let opcode = if MUTABLE {
            Opcode::MutBorrowField
        } else {
            Opcode::ImmBorrowField
        };
        let cond = cells.conditions[opcode.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2.expr() * depth_of_addr_path_expr.clone();
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

        for (i, item) in self.word_b.iter().enumerate().take(DEPTH_OF_ADDRESS_PATH) {
            lookups.rw_lookups.push((
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                ),
                cond.clone() * (1.expr() - self.ref_val_mask[i].expression.clone()),
            ));

            lookups.rw_lookups.push((
                RWLookup::stack_push(
                    cells.gc.expression.clone()
                        + depth_of_addr_path_expr.clone()
                        + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                ),
                cond.clone() * (1.expr() - self.word_b_mask[i].expression.clone()),
            ));
        }

        // field_offset is pushed into the last element of word
        let field_offset = cells.auxiliary_2.expression.clone();
        for i in 0..DEPTH_OF_ADDRESS_PATH {
            let constraint = cond.clone()
                * self.ref_val_mask[i].expression.clone()
                * (1.expr() - self.word_b_mask[i].expression.clone())
                * (field_offset.clone() - self.word_b[i].expression.clone());
            cb.add_constraint("borrow_field_offset_eq", constraint);
        }

        LookupBytecode::lookup_bytecode(
            cells,
            opcode,
            cells.auxiliary_1.expression.clone(),
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
        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;
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
            step.gc + DEPTH_OF_ADDRESS_PATH,
            word_element_num + 1, // the last element is field_offset
        )?;

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

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let word_b = cb.alloc_n_cells(WORD_CAPACITY);
        let word_b_mask = cb.alloc_n_cells(WORD_CAPACITY);
        let word_b_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let word_b_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);
        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);

        Self {
            word_b,
            word_b_mask,
            word_b_addr_ext_0,
            word_b_addr_ext_1,
            ref_val,
            ref_val_mask,
        }
    }
}
