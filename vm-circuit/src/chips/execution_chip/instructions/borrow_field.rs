// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{AddrExt, LookupBytecode, RefVal, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::{BYTES_NUM, MAX_ADDRESS_EXT_LENGTH};
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr, FieldBytes};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use movelang::value::{DEPTH_OF_ADDRESS_PATH, DEPTH_OF_LOCATION_PATH};

#[derive(Clone, Debug)]
pub struct BorrowField<const MUTABLE: bool, const GENERIC: bool, F: FieldExt> {
    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,
    word_val: Vec<Cell<F>>,
    word_val_mask: Vec<Cell<F>>,
    ref_val_addr_ext_bytes: Vec<Cell<F>>,
    ref_val_addr_ext_bytes_mask: Vec<Cell<F>>,
    word_val_addr_ext_bytes: Vec<Cell<F>>,
    word_val_addr_ext_bytes_mask: Vec<Cell<F>>,
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
        let cond = cells.conditions[Self::OPCODE.index()].expression.clone();

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
                cond.clone(),
            ));
        }

        for (i, item) in self.word_val.iter().enumerate().take(DEPTH_OF_ADDRESS_PATH) {
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
                cond.clone(),
            ));
        }

        // check for ref_val and word_val
        // ensure addr_ext equal to bytes
        let addr_ext = self
            .ref_val
            .get(2)
            .expect("addr_ext is not exsit")
            .expression
            .clone();
        let bytes = FieldBytes::from(self.ref_val_addr_ext_bytes.clone())
            .expr_16bit(MAX_ADDRESS_EXT_LENGTH);
        let constraint = cond.clone() * (addr_ext - bytes);
        cb.add_constraint("borrow_field: addr_ext bytes check 0", constraint);

        let addr_ext = self
            .word_val
            .get(2)
            .expect("addr_ext is not exsit")
            .expression
            .clone();
        let bytes = FieldBytes::from(self.word_val_addr_ext_bytes.clone())
            .expr_16bit(MAX_ADDRESS_EXT_LENGTH);
        let constraint = cond.clone() * (addr_ext - bytes);
        cb.add_constraint("borrow_field: addr_ext bytes check 1", constraint);

        // location check between ref_val and word_val
        AddrExt::location_val_constrain(cb, cond.clone(), &self.ref_val, &self.word_val)
            .expect("location chck failed");

        // addr_ext equal between ref_val and word_val
        // skip
        for i in 0..MAX_ADDRESS_EXT_LENGTH {
            let constraint = cond.clone()
                * (1.expr() - self.ref_val_addr_ext_bytes_mask[i].expression.clone())
                * (self.ref_val_addr_ext_bytes[i].expression.clone()
                    - self.word_val_addr_ext_bytes[i].expression.clone());
            cb.add_constraint("borrow_field: addr_ext_eq", constraint);
        }

        // field_offset is pushed into the last element of word,
        // and it's larger than the real offset by 1
        let field_offset = cells.auxiliary_2.expression.clone();
        for i in 0..MAX_ADDRESS_EXT_LENGTH {
            let constraint = cond.clone()
                * self.ref_val_addr_ext_bytes_mask[i].expression.clone()
                * (1.expr() - self.word_val_addr_ext_bytes_mask[i].expression.clone())
                * (field_offset.clone() + 1.expr()
                    - self.word_val_addr_ext_bytes[i].expression.clone());
            cb.add_constraint("borrow_field_offset_eq", constraint);
        }

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

        let ref_val_addr_ext = AddrExt {
            bytes: self.ref_val_addr_ext_bytes.clone(),
        };
        ref_val_addr_ext.assign_bytes(region, offset, step, step.gc + 2, rw_operations)?;

        let word = RefVal {
            ref_val: self.word_val.clone(),
            ref_val_mask: self.word_val_mask.clone(),
        };
        Word::assign_ref_val(
            region,
            offset,
            step,
            rw_operations,
            &word,
            step.gc + DEPTH_OF_ADDRESS_PATH,
            DEPTH_OF_ADDRESS_PATH,
        )?;

        let word_val_addr_ext = AddrExt {
            bytes: self.word_val_addr_ext_bytes.clone(),
        };
        word_val_addr_ext.assign_bytes(
            region,
            offset,
            step,
            step.gc + DEPTH_OF_ADDRESS_PATH + 2,
            rw_operations,
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

        // assign bytes mask
        // there is DEPTH_OF_LOCATION_PATH bits tophead.
        for i in 0..(word_element_num - DEPTH_OF_LOCATION_PATH) {
            self.ref_val_addr_ext_bytes_mask[i].assign(region, offset, Some(F::zero()))?;
        }
        for i in (word_element_num - DEPTH_OF_LOCATION_PATH)..MAX_ADDRESS_EXT_LENGTH {
            self.ref_val_addr_ext_bytes_mask[i].assign(region, offset, Some(F::one()))?;
        }
        for i in 0..(word_element_num - DEPTH_OF_LOCATION_PATH + 1) {
            self.word_val_addr_ext_bytes_mask[i].assign(region, offset, Some(F::zero()))?;
        }
        for i in (word_element_num - DEPTH_OF_LOCATION_PATH + 1)..MAX_ADDRESS_EXT_LENGTH {
            self.word_val_addr_ext_bytes_mask[i].assign(region, offset, Some(F::one()))?;
        }

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let word_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let word_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        // BYTES_NUM is adapt to FieldBytes::from, only use MAX_ADDRESS_EXT_LENGTH.
        let ref_val_addr_ext_bytes = cb.alloc_n_cells(BYTES_NUM);
        let ref_val_addr_ext_bytes_mask = cb.alloc_n_cells(BYTES_NUM);
        let word_val_addr_ext_bytes = cb.alloc_n_cells(BYTES_NUM);
        let word_val_addr_ext_bytes_mask = cb.alloc_n_cells(BYTES_NUM);

        Self {
            ref_val,
            ref_val_mask,
            word_val,
            word_val_mask,
            ref_val_addr_ext_bytes,
            ref_val_addr_ext_bytes_mask,
            word_val_addr_ext_bytes,
            word_val_addr_ext_bytes_mask,
        }
    }
}
