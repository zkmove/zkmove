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
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::value::DEPTH_OF_ADDRESS_PATH;

#[derive(Clone, Debug)]
pub struct BorrowGlobal<const MUTABLE: bool, F: FieldExt> {
    value_a: Cell<F>,
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,
    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,
}

impl<const MUTABLE: bool, F: FieldExt> InstructionGadget<F> for BorrowGlobal<MUTABLE, F> {
    const NAME: &'static str = "BORROWGLOBAL";

    const OPCODE: Opcode = if MUTABLE {
        Opcode::MutBorrowGlobal
    } else {
        Opcode::ImmBorrowGlobal
    };
    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let opcode = if MUTABLE {
            Opcode::MutBorrowGlobal
        } else {
            Opcode::ImmBorrowGlobal
        };
        let cond = cells.conditions[opcode.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_elem_num_expr = cells.auxiliary_3.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 1.expr()
            + depth_of_addr_path_expr
            + word_elem_num_expr.clone();
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

        let account_address_expr = self.value_a.expression.clone(); // address
        let sd_index_expr = cells.auxiliary_1.expression.clone(); //sd_index
        lookups.rw_lookups.push((
            "borrow global(stack pop)",
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                account_address_expr.clone(),
                0.expr(),
            ),
            cond.clone(),
        ));

        for i in 0..WORD_CAPACITY {
            lookups.rw_lookups.push((
                "borrow_global(global read)",
                RWLookup::global_read(
                    cells.gc.expression.clone() + (i as u64 + 1).expr(),
                    account_address_expr.clone(),
                    self.word_a[i].expression.clone(),
                    0.expr(), //fixme, value_ext may not be 0.
                    sd_index_expr.clone(),
                    self.word_a_addr_ext_0[i].expression.clone(),
                    self.word_a_addr_ext_1[i].expression.clone(),
                ),
                cond.clone() * (1.expr() - self.word_a_mask[i].expression.clone()),
            ));
        }

        for (i, item) in self.ref_val.iter().enumerate().take(DEPTH_OF_ADDRESS_PATH) {
            lookups.rw_lookups.push((
                "borrow_global(stack push)",
                RWLookup::stack_push(
                    cells.gc.expression.clone()
                        + word_elem_num_expr.clone()
                        + (i as u64 + 1).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                    0.expr(),
                ),
                cond.clone(),
            ));
        }

        // ref_val[0] == account_address && ref_val[1] == sd_index;
        let mut constraint =
            cond.clone() * (self.ref_val[0].expression.clone() - account_address_expr);
        cb.add_constraint("borrow_global_ref_eq", constraint);
        constraint = cond.clone() * (self.ref_val[1].expression.clone() - sd_index_expr.clone());
        cb.add_constraint("borrow_global_ref_eq", constraint);

        LookupBytecode::lookup_bytecode(
            cells,
            opcode,
            sd_index_expr,
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
        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        self.value_a.assign(region, offset, op.value().value())?;

        cells.auxiliary_1.assign(
            region,
            offset,
            step.auxiliary_1
                .as_ref()
                .expect("sd_index should not be None")
                .value(),
        )?;

        let word_elem_num = Word::get_word_element_num(region, offset, step, cells)?;
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
            step.gc + 1,
            word_elem_num,
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
            step.gc + 1 + word_elem_num,
            DEPTH_OF_ADDRESS_PATH,
        )?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = cb.alloc_cell();
        let word_a = cb.alloc_n_cells(WORD_CAPACITY);
        let word_a_mask = cb.alloc_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);
        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);

        Self {
            value_a,
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            word_a_addr_ext_1,
            ref_val,
            ref_val_mask,
        }
    }
}
