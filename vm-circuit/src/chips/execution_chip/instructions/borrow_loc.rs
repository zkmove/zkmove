// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, RefVal, Word};
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
use movelang::value::DEPTH_OF_ADDRESS_PATH;

#[derive(Clone, Debug)]
pub struct BorrowLoc<const MUTABLE: bool, F: FieldExt> {
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,
    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,
}

impl<const MUTABLE: bool, F: FieldExt> InstructionGadget<F> for BorrowLoc<MUTABLE, F> {
    const NAME: &'static str = "BORROWLOC";

    const OPCODE: Opcode = if MUTABLE {
        Opcode::MutBorrowLoc
    } else {
        Opcode::ImmBorrowLoc
    };

    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.opcode_selector([Self::OPCODE]);

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            + 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + word_element_num.clone()
            + (DEPTH_OF_ADDRESS_PATH as u64).expr();
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

        for i in 0..WORD_CAPACITY {
            let read = RWLookup::locals_ref(
                cells.gc.expression.clone() + (i as u64).expr(),
                cells.frame_index.expression.clone(),
                cells.locals_index.expression.clone(),
                self.word_a_addr_ext_0[i].expression.clone(),
                self.word_a_addr_ext_1[i].expression.clone(),
                self.word_a[i].expression.clone(),
                0.expr(),
            );

            lookups.rw_lookups.push((
                "borrow_local(local ref)",
                read,
                cond.clone() * (1.expr() - self.word_a_mask[i].expression.clone()),
            ));
        }

        for (i, item) in self.ref_val.iter().enumerate().take(DEPTH_OF_ADDRESS_PATH) {
            lookups.rw_lookups.push((
                "borrow_local(stack push)",
                RWLookup::stack_push(
                    cells.gc.expression.clone() + word_element_num.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                    0.expr(), //fixme, value_ext may not be 0.
                ),
                cond.clone(),
            ));
        }

        // ref_val[0] == frame_index && ref_val[1] == locals_index;
        let mut constraint = cond.clone()
            * (self.ref_val[0].expression.clone() - cells.frame_index.expression.clone());
        cb.add_constraint("borrow_locals_ref_eq", constraint);
        constraint = cond.clone()
            * (self.ref_val[1].expression.clone() - cells.locals_index.expression.clone());
        cb.add_constraint("borrow_locals_ref_eq", constraint);

        LookupBytecode::lookup_bytecode(
            cells,
            Self::OPCODE,
            cells.locals_index.expression.clone(),
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
        let word = Word {
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
            &word,
            step.gc,
            word_element_num,
        )?;

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
            step.gc + word_element_num,
            DEPTH_OF_ADDRESS_PATH,
        )?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let word_a = cb.alloc_n_cells(WORD_CAPACITY);
        let word_a_mask = cb.alloc_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);
        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);

        Self {
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            word_a_addr_ext_1,
            ref_val,
            ref_val_mask,
        }
    }
}
