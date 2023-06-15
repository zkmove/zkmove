// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, RefVal, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::word_capacity;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::word::ValueHeader;
use movelang::word::LEN_OF_REFERENCE_VALUE;

#[derive(Clone, Debug)]
pub struct BorrowLoc<const MUTABLE: bool, F: FieldExt> {
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
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

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            + 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + word_element_num.clone()
            + (LEN_OF_REFERENCE_VALUE as u64).expr();
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();
        cb.add_constraints(vec![
            ("pc", pc_expr),
            ("stack size", stack_size_expr),
            ("frame index", frame_index_expr),
            ("gc", gc_expr),
            ("module index", module_index),
            ("function index", func_index),
        ]);

        for (i, _) in self.word_a.iter().enumerate() {
            cb.condition(1.expr() - self.word_a_mask[i].expression.clone(), |cb| {
                let read = RWLookup::locals_read(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.frame_index.expression.clone(),
                    cells.locals_index.expression.clone(),
                    self.word_a_addr_ext_0[i].expression.clone(),
                    self.word_a[i].expression.clone(),
                );

                cb.add_lookup("borrow_local(read locals)", read);
            });
        }

        for (i, item) in self.ref_val.iter().enumerate() {
            cb.add_lookup(
                "borrow_local(stack push ref_val)",
                RWLookup::stack_push(
                    cells.gc.expression.clone() + word_element_num.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    item.expression.clone(),
                ),
            );
        }

        // ref_val[1] == frame_index && ref_val[2] == locals_index;
        cb.add_constraint(
            "borrow_locals_ref_eq_0",
            self.ref_val[0].expression.clone() - ValueHeader::default_for_ref_val().expr(),
        );
        cb.add_constraint(
            "borrow_locals_ref_eq_1",
            self.ref_val[1].expression.clone() - cells.frame_index.expression.clone(),
        );
        cb.add_constraint(
            "borrow_locals_ref_eq_2",
            self.ref_val[2].expression.clone() - cells.locals_index.expression.clone(),
        );
        cb.add_constraint("borrow_locals_ref_eq_3", self.ref_val[3].expression.clone());

        LookupBytecode::lookup_bytecode(
            cb,
            cells,
            Self::OPCODE,
            cells.locals_index.expression.clone(),
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
            LEN_OF_REFERENCE_VALUE,
        )?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let word_cap = word_capacity();

        // alloc cell
        let word_a = cb.alloc_n_cells(word_cap);
        let word_a_mask = cb.alloc_n_cells(word_cap);
        let word_a_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let ref_val = cb.alloc_n_cells(LEN_OF_REFERENCE_VALUE);
        let ref_val_mask = cb.alloc_n_cells(LEN_OF_REFERENCE_VALUE);

        Self {
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            ref_val,
            ref_val_mask,
        }
    }
}
