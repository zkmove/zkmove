// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{AddrExt, LookupBytecode, RefVal, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
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
pub struct BorrowField<const MUTABLE: bool, const GENERIC: bool, F: FieldExt> {
    offset_pow2: Cell<F>,
    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,
    indexed_ref_val: Vec<Cell<F>>,
    indexed_ref_val_mask: Vec<Cell<F>>,
}

impl<const MUTABLE: bool, const GENERIC: bool, F: FieldExt> InstructionGadget<F>
    for BorrowField<MUTABLE, GENERIC, F>
{
    const NAME: &'static str = match (MUTABLE, GENERIC) {
        (true, true) => "MUT_BORROW_FIELD_GENERIC",
        (true, false) => "MUT_BORROW_FIELD",
        (false, true) => "IMM_BORROW_FIELD_GENERIC",
        (false, false) => "IMM_BORROW_FIELD",
    };

    const OPCODE: Opcode = match (MUTABLE, GENERIC) {
        (true, true) => Opcode::MutBorrowFieldGeneric,
        (true, false) => Opcode::MutBorrowField,
        (false, true) => Opcode::ImmBorrowFieldGeneric,
        (false, false) => Opcode::ImmBorrowField,
    };

    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        // for instruction Mut(Imm)BorrowField, there are 2 steps here:
        // 1. read reference from stack. [gc, DEPTH_OF_ADDRESS_PATH]
        // 2. write reference to element into stack.
        // [gc + DEPTH_OF_ADDRESS_PATH, DEPTH_OF_ADDRESS_PATH]
        let cond = cells.opcode_selector([Self::OPCODE]);

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

        // lookup
        for (i, item) in self.ref_val.iter().enumerate().take(DEPTH_OF_ADDRESS_PATH) {
            lookups.rw_lookups.push((
                "borrow_field(stack pop)",
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                    0.expr(),
                ),
                cond.clone() * (1.expr() - self.ref_val_mask[i].expression.clone()),
            ));
        }

        for (i, item) in self
            .indexed_ref_val
            .iter()
            .enumerate()
            .take(DEPTH_OF_ADDRESS_PATH)
        {
            lookups.rw_lookups.push((
                "borrow_field(stack push)",
                RWLookup::stack_push(
                    cells.gc.expression.clone()
                        + depth_of_addr_path_expr.clone()
                        + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                    0.expr(),
                ),
                cond.clone() * (1.expr() - self.indexed_ref_val_mask[i].expression.clone()),
            ));
        }

        // location check between ref_val and indexed_ref_val
        AddrExt::location_val_constrain(cb, cond.clone(), &self.ref_val, &self.indexed_ref_val)
            .expect("location check failed");

        // addr_ext check between ref_val and indexed_ref_val
        // field_offset is pushed into the last element of indexed_ref_val,
        // and it's larger than the real offset by 1
        let offset = &cells.auxiliary_2; // field_offset
        let constraint = cond.clone()
            * (self.ref_val[2].expression.clone()
                + (offset.expression.clone() + 1.expr()) * self.offset_pow2.expression.clone()
                - self.indexed_ref_val[2].expression.clone())
            * (1.expr() - self.ref_val_mask[2].expression.clone());
        cb.add_constraint("field_offset check with ref_val[2]", constraint);

        LookupBytecode::lookup_bytecode(
            cells,
            Self::OPCODE,
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
        let _pow2 = Word::assign_offset_pow2(region, offset, &step.auxiliary_3, &self.offset_pow2)?
            .get_lower_128() as usize;
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

        let indexed_ref_val = RefVal {
            ref_val: self.indexed_ref_val.clone(),
            ref_val_mask: self.indexed_ref_val_mask.clone(),
        };
        Word::assign_ref_val(
            region,
            offset,
            step,
            rw_operations,
            &indexed_ref_val,
            step.gc + DEPTH_OF_ADDRESS_PATH,
            DEPTH_OF_ADDRESS_PATH,
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
        let offset_pow2 = cb.alloc_cell();

        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let indexed_ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let indexed_ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);

        Self {
            offset_pow2,
            ref_val,
            ref_val_mask,
            indexed_ref_val,
            indexed_ref_val_mask,
        }
    }
}
