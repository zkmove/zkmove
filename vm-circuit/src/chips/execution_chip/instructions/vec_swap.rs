// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, RefVal, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::word_capacity;

use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use fields::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::word::ValueHeader;
use movelang::word::LEN_OF_REFERENCE_VALUE;

#[derive(Clone, Debug)]
pub struct VecSwap<F: FieldExt> {
    idx_a: Cell<F>,
    idx_b: Cell<F>,
    offset_pow2: Cell<F>,

    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,

    vec_frame_index_or_global_address: Cell<F>,
    vec_locals_index_or_global_sd_idx: Cell<F>,

    value_a: Vec<Cell<F>>,
    value_a_mask: Vec<Cell<F>>,
    value_a_addr_ext_0: Vec<Cell<F>>,
    value_a_addr_ext_1: Vec<Cell<F>>,

    value_b: Vec<Cell<F>>,
    value_b_mask: Vec<Cell<F>>,
    value_b_addr_ext_0: Vec<Cell<F>>,
    value_b_addr_ext_1: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for VecSwap<F> {
    const NAME: &'static str = "VEC_SWAP";

    const OPCODE: Opcode = Opcode::VecSwap;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // for instruction VecSwap, there are 7 steps here:
        // 1. read idx_b from stack [gc, 2]
        // 2. read idx_a from stack [gc + 2, 2]
        // 3. read vec ref from stack. [gc + 4, LEN_OF_REFERENCE_VALUE]
        // 4. read value_a from vec (in locals or global).
        // [gc + 4 + LEN_OF_REFERENCE_VALUE, value_a_flattened_len]
        // 5. read value_b from vec (in locals or global).
        // [gc + 4 + LEN_OF_REFERENCE_VALUE + value_a_flattened_len, value_b_flattened_len]
        // 6. write value_a to vec (in locals or global).
        // [gc + 4 + LEN_OF_REFERENCE_VALUE + value_a_flattened_len + value_b_flattened_len,
        // value_a_flattened_len]
        // 7. write value_b to vec (in locals or global).
        // [gc + 4 + LEN_OF_REFERENCE_VALUE + 2 * value_a_flattened_len + value_b_flattened_len,
        // value_b_flattened_len]

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 3.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let value_a_flattened_len = cells.auxiliary_2.expression.clone();
        let value_b_flattened_len = cells.auxiliary_3.expression.clone();

        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 4.expr()
            + (LEN_OF_REFERENCE_VALUE as u64).expr()
            + value_a_flattened_len.clone() * 2.expr()
            + value_b_flattened_len.clone() * 2.expr();
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

        cb.add_lookup(
            "vec_borrow(read idx_b value header)",
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "vec_swap(pop idx_b)",
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone(),
                1.expr(),
                0.expr(),
                self.idx_b.expression.clone(),
            ),
        );
        cb.add_lookup(
            "vec_borrow(read idx_a value header)",
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 2.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                0.expr(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "vec_swap(pop idx_a)",
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 3.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                1.expr(),
                0.expr(),
                self.idx_a.expression.clone(),
            ),
        );

        // read reference from stack
        for (i, item) in self.ref_val.iter().enumerate() {
            cb.condition(1.expr() - self.ref_val_mask[i].expression.clone(), |cb| {
                cb.add_lookup(
                    "vec_swap(read vec ref)",
                    RWLookup::stack_pop(
                        cells.gc.expression.clone() + 4.expr() + (i as u64).expr(),
                        cells.stack_size.expression.clone() - 2.expr(),
                        (i as u64).expr(),
                        0.expr(),
                        item.expression.clone(),
                    ),
                );
            });
        }

        let is_global = cells.auxiliary_5.expression.clone();

        for (i, item) in self.value_a.iter().enumerate() {
            cb.condition(1.expr() - self.value_a_mask[i].expression.clone(), |cb| {
                cb.condition(1.expr() - is_global.clone(), |cb| {
                    // read value_a
                    let locals_read = RWLookup::locals_read(
                        cells.gc.expression.clone()
                            + 4.expr()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + (i as u64).expr(),
                        self.vec_frame_index_or_global_address.expression.clone(),
                        self.vec_locals_index_or_global_sd_idx.expression.clone(),
                        self.value_a_addr_ext_0[i].expression.clone(),
                        self.value_a_addr_ext_1[i].expression.clone(),
                        item.expression.clone(),
                    );
                    cb.add_lookup("vec_swap(read value_a)", locals_read);
                    // write value_a
                    let locals_write = RWLookup::locals_write(
                        cells.gc.expression.clone()
                            + 4.expr()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + value_a_flattened_len.clone()
                            + value_b_flattened_len.clone()
                            + (i as u64).expr(),
                        self.vec_frame_index_or_global_address.expression.clone(),
                        self.vec_locals_index_or_global_sd_idx.expression.clone(),
                        self.value_b_addr_ext_0[i].expression.clone(),
                        self.value_b_addr_ext_1[i].expression.clone(),
                        item.expression.clone(),
                    );
                    cb.add_lookup("vec_swap(write value_a)", locals_write);
                });
                cb.condition(is_global.clone(), |cb| {
                    let global_read = RWLookup::global_read(
                        cells.gc.expression.clone()
                            + 4.expr()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + (i as u64).expr(),
                        self.vec_frame_index_or_global_address.expression.clone(),
                        item.expression.clone(),
                        self.vec_locals_index_or_global_sd_idx.expression.clone(),
                        self.value_a_addr_ext_0[i].expression.clone(),
                        self.value_a_addr_ext_1[i].expression.clone(),
                    );
                    cb.add_lookup("vec_swap(read value_a)", global_read);

                    let global_write = RWLookup::global_write(
                        cells.gc.expression.clone()
                            + 4.expr()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + value_a_flattened_len.clone()
                            + value_b_flattened_len.clone()
                            + (i as u64).expr(),
                        self.vec_frame_index_or_global_address.expression.clone(),
                        item.expression.clone(),
                        self.vec_locals_index_or_global_sd_idx.expression.clone(),
                        self.value_b_addr_ext_0[i].expression.clone(),
                        self.value_b_addr_ext_1[i].expression.clone(),
                    );
                    cb.add_lookup("vec_swap(write value_a)", global_write);
                });
            });
        }

        for (i, item) in self.value_b.iter().enumerate() {
            cb.condition(1.expr() - self.value_b_mask[i].expression.clone(), |cb| {
                cb.condition(1.expr() - is_global.clone(), |cb| {
                    // read value_b
                    let locals_read = RWLookup::locals_read(
                        cells.gc.expression.clone()
                            + 4.expr()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + value_a_flattened_len.clone()
                            + (i as u64).expr(),
                        self.vec_frame_index_or_global_address.expression.clone(),
                        self.vec_locals_index_or_global_sd_idx.expression.clone(),
                        self.value_b_addr_ext_0[i].expression.clone(),
                        self.value_b_addr_ext_1[i].expression.clone(),
                        item.expression.clone(),
                    );
                    cb.add_lookup("vec_swap(read value_b)", locals_read);
                    // write value_b
                    let locals_write = RWLookup::locals_write(
                        cells.gc.expression.clone()
                            + 4.expr()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + 2.expr() * value_a_flattened_len.clone()
                            + value_b_flattened_len.clone()
                            + (i as u64).expr(),
                        self.vec_frame_index_or_global_address.expression.clone(),
                        self.vec_locals_index_or_global_sd_idx.expression.clone(),
                        self.value_a_addr_ext_0[i].expression.clone(),
                        self.value_a_addr_ext_1[i].expression.clone(),
                        item.expression.clone(),
                    );
                    cb.add_lookup("vec_swap(write value_b)", locals_write);
                });
                cb.condition(is_global.clone(), |cb| {
                    let global_read = RWLookup::global_read(
                        cells.gc.expression.clone()
                            + 4.expr()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + value_a_flattened_len.clone()
                            + (i as u64).expr(),
                        self.vec_frame_index_or_global_address.expression.clone(),
                        item.expression.clone(),
                        self.vec_locals_index_or_global_sd_idx.expression.clone(),
                        self.value_b_addr_ext_0[i].expression.clone(),
                        self.value_b_addr_ext_1[i].expression.clone(),
                    );
                    cb.add_lookup("vec_swap(read value_b)", global_read);
                    let global_write = RWLookup::global_write(
                        cells.gc.expression.clone()
                            + 4.expr()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + 2.expr() * value_a_flattened_len.clone()
                            + value_b_flattened_len.clone()
                            + (i as u64).expr(),
                        self.vec_frame_index_or_global_address.expression.clone(),
                        item.expression.clone(),
                        self.vec_locals_index_or_global_sd_idx.expression.clone(),
                        self.value_a_addr_ext_0[i].expression.clone(),
                        self.value_a_addr_ext_1[i].expression.clone(),
                    );
                    cb.add_lookup("vec_swap(write value_b)", global_write);
                });
            });
        }

        // Constrains ref_val[0] equals to ref value header
        let constraint = (self.ref_val[0].expression.clone()
            - ValueHeader::default_for_ref_val().expr())
            * (1.expr() - self.ref_val_mask[0].expression.clone());
        cb.add_constraint("read_ref_eq_0", constraint);

        // Constrains ref_val[1] == vec_frame_index_or_global_address.
        let constraint = (self.ref_val[1].expression.clone()
            - self.vec_frame_index_or_global_address.expression.clone())
            * (1.expr() - self.ref_val_mask[1].expression.clone());
        cb.add_constraint("ref_check_1", constraint);

        // Constrains ref_val[2] == vec_locals_index_or_global_sd_idx.
        let constraint = (self.ref_val[2].expression.clone()
            - self.vec_locals_index_or_global_sd_idx.expression.clone())
            * (1.expr() - self.ref_val_mask[2].expression.clone());
        cb.add_constraint("ref_check_2", constraint);

        // Constrains ref_val[3] == value_a_address_path[2, ref_val_flattened_len].
        // Constrains ref_val[3] == value_b_address_path[2, ref_val_flattened_len].
        // value_a is read from idx_a, value_b is read from idx_b
        // idx_a + 1 == value_a_address_path[last]
        // idx_b + 1 == value_b_address_path[last]
        // counting the header, it's 1 larger than the real offset
        let constraint = (self.ref_val[3].expression.clone()
            + (self.idx_a.expression.clone() + 1.expr()) * self.offset_pow2.expression.clone()
            - self.value_a_addr_ext_0[0].expression.clone())
            * (1.expr() - self.ref_val_mask[3].expression.clone());
        cb.add_constraint("value_a's address check with ref_val[3]", constraint);
        let constraint = (self.ref_val[3].expression.clone()
            + (self.idx_b.expression.clone() + 1.expr()) * self.offset_pow2.expression.clone()
            - self.value_b_addr_ext_0[0].expression.clone())
            * (1.expr() - self.ref_val_mask[3].expression.clone());
        cb.add_constraint("value_b's address check with ref_val[3]", constraint);

        LookupBytecode::lookup_bytecode(
            cb,
            cells,
            Opcode::VecSwap,
            cells.auxiliary_1.expression.clone(),
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
        let _si = Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;
        let value_a_flattened_len =
            Word::assign_step_value(region, offset, &step.auxiliary_2, &cells.auxiliary_2)?
                .get_lower_128() as usize;
        let value_b_flattened_len =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;
        let ref_val_flattened_len =
            Word::assign_step_value(region, offset, &step.auxiliary_4, &cells.auxiliary_4)?
                .get_lower_128() as usize;
        let _pow2 = Word::assign_offset_pow2(region, offset, &step.auxiliary_4, &self.offset_pow2)?
            .get_lower_128() as usize;
        let is_global =
            Word::assign_step_value(region, offset, &step.auxiliary_5, &cells.auxiliary_5)?;

        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        self.idx_b.assign(region, offset, op.value().value())?;
        let op = rw_operations.0.get(step.gc + 3).ok_or(Error::Synthesis)?;
        self.idx_a.assign(region, offset, op.value().value())?;

        // assign vector ref
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
            step.gc + 4,
            ref_val_flattened_len,
        )?;

        let op = rw_operations
            .0
            .get(step.gc + 4 + LEN_OF_REFERENCE_VALUE)
            .ok_or(Error::Synthesis)?;

        if is_global == F::ZERO {
            self.vec_frame_index_or_global_address.assign(
                region,
                offset,
                Some(F::from(op.frame_index() as u64)),
            )?;
            self.vec_locals_index_or_global_sd_idx.assign(
                region,
                offset,
                Some(F::from(op.address() as u64)),
            )?;
        } else {
            self.vec_frame_index_or_global_address.assign(
                region,
                offset,
                Some(op.account_address().value()),
            )?;
            self.vec_locals_index_or_global_sd_idx.assign(
                region,
                offset,
                Some(F::from(op.sd_index() as u64)),
            )?;
        }

        // assign value_a
        let value_a = Word {
            word: self.value_a.clone(),
            word_mask: self.value_a_mask.clone(),
            word_addr_ext_0: self.value_a_addr_ext_0.clone(),
            word_addr_ext_1: self.value_a_addr_ext_1.clone(),
        };
        Word::assign_word(
            region,
            offset,
            step,
            rw_operations,
            &value_a,
            step.gc + 4 + LEN_OF_REFERENCE_VALUE,
            value_a_flattened_len,
        )?;

        // assign value_b
        let value_b = Word {
            word: self.value_b.clone(),
            word_mask: self.value_b_mask.clone(),
            word_addr_ext_0: self.value_b_addr_ext_0.clone(),
            word_addr_ext_1: self.value_b_addr_ext_1.clone(),
        };
        Word::assign_word(
            region,
            offset,
            step,
            rw_operations,
            &value_b,
            step.gc + 4 + LEN_OF_REFERENCE_VALUE + value_a_flattened_len,
            value_b_flattened_len,
        )?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let word_cap = word_capacity();

        // alloc cell
        let idx_a = cb.alloc_cell();
        let idx_b = cb.alloc_cell();
        let offset_pow2 = cb.alloc_cell();

        let ref_val = cb.alloc_n_cells(LEN_OF_REFERENCE_VALUE);
        let ref_val_mask = cb.alloc_n_cells(LEN_OF_REFERENCE_VALUE);

        let vec_frame_index_or_global_address = cb.alloc_cell();
        let vec_locals_index_or_global_sd_idx = cb.alloc_cell();

        let value_a = cb.alloc_n_cells(word_cap);
        let value_a_mask = cb.alloc_n_cells(word_cap);
        let value_a_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let value_a_addr_ext_1 = cb.alloc_n_cells(word_cap);

        let value_b = cb.alloc_n_cells(word_cap);
        let value_b_mask = cb.alloc_n_cells(word_cap);
        let value_b_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let value_b_addr_ext_1 = cb.alloc_n_cells(word_cap);

        Self {
            idx_a,
            idx_b,
            offset_pow2,

            ref_val,
            ref_val_mask,

            vec_frame_index_or_global_address,
            vec_locals_index_or_global_sd_idx,

            value_a,
            value_a_mask,
            value_a_addr_ext_0,
            value_a_addr_ext_1,

            value_b,
            value_b_mask,
            value_b_addr_ext_0,
            value_b_addr_ext_1,
        }
    }
}
