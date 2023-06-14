// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{AddrExt, LookupBytecode, RefVal, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::{word_capacity, MAX_ADDRESS_EXT_LENGTH};
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::value::DEPTH_OF_LOCATION_PATH;
use movelang::word::ValueHeader;
use movelang::word::LEN_OF_REFERENCE_VALUE;

#[derive(Clone, Debug)]
pub struct VecPopBack<F: FieldExt> {
    headers_count: Cell<F>,
    value_index: Cell<F>,
    offset_pow2: Cell<F>,

    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,
    ref_val_addr_ext_mask_0: Vec<Cell<F>>,
    ref_val_addr_ext_mask_1: Vec<Cell<F>>,

    vec_frame_index_or_global_address: Cell<F>,
    vec_locals_index_or_global_sd_idx: Cell<F>,

    value: Vec<Cell<F>>,
    value_mask: Vec<Cell<F>>,
    value_addr_ext_0: Vec<Cell<F>>,
    value_addr_ext_1: Vec<Cell<F>>,

    new_value_addr_ext_0: Vec<Cell<F>>,
    new_value_addr_ext_1: Vec<Cell<F>>,

    headers_value: Vec<Cell<F>>,
    headers_value_mask: Vec<Cell<F>>,
    headers_value_addr_ext_0: Vec<Cell<F>>,
    headers_value_addr_ext_1: Vec<Cell<F>>,

    new_headers_value: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for VecPopBack<F> {
    const NAME: &'static str = "VEC_POP_BACK";

    const OPCODE: Opcode = Opcode::VecPopBack;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // for instruction VecPopBack, there are 4 steps here:
        // 1. read vec ref from stack. [gc, LEN_OF_REFERENCE_VALUE]
        // 2. read value from vec (in locals or global).
        // [gc + LEN_OF_REFERENCE_VALUE, value_flattened_len]
        // 3. write value to stack.
        // [gc + LEN_OF_REFERENCE_VALUE + value_flattened_len, value_flattened_len]
        // 4. update current and parent headers (flattened_length, length).
        // [gc + LEN_OF_REFERENCE_VALUE + value_flattened_len * 2, headers_count * 2]

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let value_flattened_len = cells.auxiliary_3.expression.clone();
        let ref_val_flattened_len = cells.auxiliary_4.expression.clone();
        let headers_count = self.headers_count.expression.clone();

        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2.expr() * value_flattened_len.clone()
            + (LEN_OF_REFERENCE_VALUE as u64).expr()
            + 2.expr() * headers_count.clone();
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

        let is_global = cells.auxiliary_5.expression.clone();

        // read reference from stack
        for (i, item) in self.ref_val.iter().enumerate() {
            cb.condition(1.expr() - self.ref_val_mask[i].expression.clone(), |cb| {
                cb.add_lookup(
                    "vec_pop_back(read ref)",
                    RWLookup::stack_pop(
                        cells.gc.expression.clone() + (i as u64).expr(),
                        cells.stack_size.expression.clone(),
                        (i as u64).expr(),
                        0.expr(),
                        item.expression.clone(),
                    ),
                );
            });
        }

        for (i, item) in self.value.iter().enumerate() {
            cb.condition(1.expr() - self.value_mask[i].expression.clone(), |cb| {
                // read value from container
                cb.condition(1.expr() - is_global.clone(), |cb| {
                    let locals_read = RWLookup::locals_read(
                        cells.gc.expression.clone()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + (i as u64).expr(),
                        self.vec_frame_index_or_global_address.expression.clone(),
                        self.vec_locals_index_or_global_sd_idx.expression.clone(),
                        self.value_addr_ext_0[i].expression.clone(),
                        self.value_addr_ext_1[i].expression.clone(),
                        item.expression.clone(),
                    );
                    cb.add_lookup("vec_pop_back(read value)", locals_read);
                });
                cb.condition(is_global.clone(), |cb| {
                    let global_read = RWLookup::global_read(
                        cells.gc.expression.clone()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + (i as u64).expr(),
                        self.vec_frame_index_or_global_address.expression.clone(),
                        item.expression.clone(),
                        self.vec_locals_index_or_global_sd_idx.expression.clone(),
                        self.value_addr_ext_0[i].expression.clone(),
                        self.value_addr_ext_1[i].expression.clone(),
                    );
                    cb.add_lookup("vec_pop_back(read value)", global_read);
                });

                // write value to stack
                let write = RWLookup::stack_push(
                    cells.gc.expression.clone()
                        + (LEN_OF_REFERENCE_VALUE as u64).expr()
                        + value_flattened_len.clone()
                        + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    self.new_value_addr_ext_0[i].expression.clone(),
                    self.new_value_addr_ext_1[i].expression.clone(),
                    item.expression.clone(),
                );
                cb.add_lookup("vec_pop_back(write value)", write);
            });
        }

        // read the old value from headers and write the new value to the headers
        let gc_offset = cells.gc.expression.clone()
            + (LEN_OF_REFERENCE_VALUE as u64).expr()
            + value_flattened_len.clone() * 2.expr();
        for (i, item) in self
            .headers_value
            .iter()
            .enumerate()
            .take(MAX_ADDRESS_EXT_LENGTH)
        {
            cb.condition(
                1.expr() - self.headers_value_mask[i].expression.clone(),
                |cb| {
                    cb.condition(1.expr() - is_global.clone(), |cb| {
                        let locals_read = RWLookup::locals_read(
                            gc_offset.clone() + (i as u64).expr(),
                            self.vec_frame_index_or_global_address.expression.clone(),
                            self.vec_locals_index_or_global_sd_idx.expression.clone(),
                            self.headers_value_addr_ext_0[i].expression.clone(),
                            self.headers_value_addr_ext_1[i].expression.clone(),
                            item.expression.clone(),
                        );
                        cb.add_lookup("vec_pop_back(read headers)", locals_read);
                        let locals_write = RWLookup::locals_write(
                            gc_offset.clone() + headers_count.clone() + (i as u64).expr(),
                            self.vec_frame_index_or_global_address.expression.clone(),
                            self.vec_locals_index_or_global_sd_idx.expression.clone(),
                            self.headers_value_addr_ext_0[i].expression.clone(),
                            self.headers_value_addr_ext_1[i].expression.clone(),
                            self.new_headers_value[i].expression.clone(),
                        );
                        cb.add_lookup("vec_pop_back(write headers)", locals_write);
                    });
                    cb.condition(is_global.clone(), |cb| {
                        let global_read = RWLookup::global_read(
                            gc_offset.clone() + (i as u64).expr(),
                            self.vec_frame_index_or_global_address.expression.clone(),
                            item.expression.clone(),
                            self.vec_locals_index_or_global_sd_idx.expression.clone(),
                            self.headers_value_addr_ext_0[i].expression.clone(),
                            self.headers_value_addr_ext_1[i].expression.clone(),
                        );
                        cb.add_lookup("vec_pop_back(read headers)", global_read);
                        let global_write = RWLookup::global_write(
                            gc_offset.clone() + headers_count.clone() + (i as u64).expr(),
                            self.vec_frame_index_or_global_address.expression.clone(),
                            self.new_headers_value[i].expression.clone(),
                            self.vec_locals_index_or_global_sd_idx.expression.clone(),
                            self.headers_value_addr_ext_0[i].expression.clone(),
                            self.headers_value_addr_ext_1[i].expression.clone(),
                        );
                        cb.add_lookup("vec_pop_back(write headers)", global_write);
                    });
                },
            );
        }

        // Constrains the value to be popped from the vector referenced by vec_ref.
        // ref_val[0] equals to ref value header
        let mut constraint = (self.ref_val[0].expression.clone()
            - ValueHeader::default_for_ref_val().expr())
            * (1.expr() - self.ref_val_mask[0].expression.clone());
        cb.add_constraint("read_ref_eq_0", constraint);

        constraint = (self.ref_val[1].expression.clone()
            - self.vec_frame_index_or_global_address.expression.clone())
            * (1.expr() - self.ref_val_mask[1].expression.clone());
        cb.add_constraint("read_ref_eq_1", constraint);

        constraint = (self.ref_val[2].expression.clone()
            - self.vec_locals_index_or_global_sd_idx.expression.clone())
            * (1.expr() - self.ref_val_mask[2].expression.clone());
        cb.add_constraint("read_ref_eq_2", constraint);

        // addr_ext comparation between ref_val and indexed_ref_val
        // field_offset is pushed into the last element of indexed_ref_val,
        // and it's larger than the real offset by 1
        let offset = &self.value_index; // field_offset
        let constraint = (self.ref_val[2].expression.clone()
            + (offset.expression.clone() + 1.expr()) * self.offset_pow2.expression.clone()
            - self.value_addr_ext_0[0].expression.clone())
            * (1.expr() - self.ref_val_mask[2].expression.clone());
        cb.add_constraint("field_offset check with ref_val[2]", constraint);

        // Constrains the address of headers must be part of the vector's address path.
        // For example, if the vector has address path [3,1,2,1], the header's address will
        // be: [3,1,0,0],[3,1,2,0],[3,1,2,1]
        //
        // header[i]'s frame_index or global address must equal to ref_val[1],
        // header[i]'s locals_index or global sd_index must equal to ref_val[2],
        // already constrained by the above lookup
        // fixme: header[i]'s addr_ext_0 is not always equal to ref_val[3],
        // for i in 0..(MAX_ADDRESS_EXT_LENGTH) {
        //     let constraint = (self.ref_val_addr_ext_mask_0[i].expression.clone())
        //         * (1.expr() - self.ref_val_addr_ext_mask_1[i].expression.clone())
        //         * (self.headers_value_addr_ext_0[i].expression.clone()
        //             - self.ref_val[3].expression.clone());
        //     cb.add_constraint("check header addr_ext_0", constraint);
        // }

        // constraint on addr_ext_mask_0 and addr_ext_mask_1
        // skip DEPTH_OF_LOCATION_PATH bits tophead.
        AddrExt::constrain_mask_n(
            cb,
            &self.ref_val_addr_ext_mask_0,
            &self.ref_val_addr_ext_mask_1,
            ref_val_flattened_len - (DEPTH_OF_LOCATION_PATH as u64).expr(),
            (MAX_ADDRESS_EXT_LENGTH as u64).expr(),
        );

        // Constrains the headers are correctly updated.
        let curr_header_idx = headers_count - 1.expr();
        for i in 0..MAX_ADDRESS_EXT_LENGTH {
            // flattened_len decreased in the parent headers
            let constraint = (curr_header_idx.clone() - (i as u64).expr()) //exclude the current header
                * (1.expr() - self.headers_value_mask[i].expression.clone())
                * (self.headers_value[i].expression.clone()
                - value_flattened_len.clone()
                - self.new_headers_value[i].expression.clone());
            cb.add_constraint("parent_header_val_decreased", constraint);

            // todo: flattened_len and len decreased in the current header
            // how to apply below constraints only on the current header?
            // we need define a common method to handle this.
            //
            //     let len_diff = 1.expr() * 2u64.pow(16).expr(); //vector length decrease one
            //     let constraint = cond.clone()
            //         * (1.expr() - self.headers_value_mask[i].expression.clone())
            //         * (self.headers_value[i].expression.clone()
            //         - len_diff.clone() - value_flattened_len.clone()
            //         - self.new_headers_value[i].expression.clone());
            //     cb.add_constraint("current_header_val_decreased", constraint);
            //
        }

        LookupBytecode::lookup_bytecode(
            cb,
            cells,
            Opcode::VecPopBack,
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
        // auxiliary_2 is multiplexed by header_len and value_index.
        let val = step
            .auxiliary_2
            .as_ref()
            .unwrap()
            .value()
            .unwrap()
            .get_lower_128();
        let headers_count = (val & 0xFF) as usize;
        let value_index = ((val >> 8) & 0xFFFF) as usize; // max value_index is 2^16 - 1
        self.headers_count
            .assign(region, offset, Some(F::from_u128(headers_count as u128)))?;
        self.value_index
            .assign(region, offset, Some(F::from_u128(value_index as u128)))?;
        let value_flattened_len =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;
        let ref_val_flattened_len =
            Word::assign_step_value(region, offset, &step.auxiliary_4, &cells.auxiliary_4)?
                .get_lower_128() as usize;
        let _pow2 = Word::assign_offset_pow2(region, offset, &step.auxiliary_4, &self.offset_pow2)?
            .get_lower_128() as usize;

        let is_global =
            Word::assign_step_value(region, offset, &step.auxiliary_5, &cells.auxiliary_5)?;

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
            step.gc,
            ref_val_flattened_len,
        )?;

        let index = step.gc + LEN_OF_REFERENCE_VALUE;
        let op = rw_operations.0.get(index).ok_or(Error::Synthesis)?;
        if is_global == F::zero() {
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

        // assign value read from locals(or global)
        let value_pop = Word {
            word: self.value.clone(),
            word_mask: self.value_mask.clone(),
            word_addr_ext_0: self.value_addr_ext_0.clone(),
            word_addr_ext_1: self.value_addr_ext_1.clone(),
        };
        Word::assign_word(
            region,
            offset,
            step,
            rw_operations,
            &value_pop,
            index,
            value_flattened_len,
        )?;

        // assign bytes mask
        // skip DEPTH_OF_LOCATION_PATH bits tophead.
        let n = ref_val_flattened_len as usize - DEPTH_OF_LOCATION_PATH;
        let mask_a = &self.ref_val_addr_ext_mask_0;
        let mask_b = &self.ref_val_addr_ext_mask_1;
        AddrExt::assign_byte_n_mask(region, offset, mask_a, mask_b, n)?;

        // assign value write to stack
        let value_stack = Word {
            word: self.value.clone(),
            word_mask: self.value_mask.clone(),
            word_addr_ext_0: self.new_value_addr_ext_0.clone(),
            word_addr_ext_1: self.new_value_addr_ext_1.clone(),
        };
        Word::assign_word(
            region,
            offset,
            step,
            rw_operations,
            &value_stack,
            step.gc + LEN_OF_REFERENCE_VALUE + value_flattened_len,
            value_flattened_len,
        )?;

        let headers = Word {
            word: self.headers_value.clone(),
            word_mask: self.headers_value_mask.clone(),
            word_addr_ext_0: self.headers_value_addr_ext_0.clone(),
            word_addr_ext_1: self.headers_value_addr_ext_1.clone(),
        };
        Word::assign_word_with_capacity(
            region,
            offset,
            step,
            rw_operations,
            &headers,
            step.gc + LEN_OF_REFERENCE_VALUE + value_flattened_len * 2,
            headers_count,
            MAX_ADDRESS_EXT_LENGTH,
        )?;

        let new_headers_op_idx =
            step.gc + LEN_OF_REFERENCE_VALUE + value_flattened_len * 2 + headers_count;
        for i in 0..headers_count {
            let op = rw_operations
                .0
                .get(new_headers_op_idx + i)
                .ok_or(Error::Synthesis)?;
            self.new_headers_value[i].assign(region, offset, op.value().value())?;
        }

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let word_cap = word_capacity();
        // alloc cell
        let headers_count = cb.alloc_cell();
        let value_index = cb.alloc_cell();
        let offset_pow2 = cb.alloc_cell();

        let ref_val = cb.alloc_n_cells(LEN_OF_REFERENCE_VALUE);
        let ref_val_mask = cb.alloc_n_cells(LEN_OF_REFERENCE_VALUE);
        let ref_val_addr_ext_mask_0 = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);
        let ref_val_addr_ext_mask_1 = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);

        let vec_frame_index_or_global_address = cb.alloc_cell();
        let vec_locals_index_or_global_sd_idx = cb.alloc_cell();

        let value = cb.alloc_n_cells(word_cap);
        let value_mask = cb.alloc_n_cells(word_cap);
        let value_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let value_addr_ext_1 = cb.alloc_n_cells(word_cap);

        let new_value_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let new_value_addr_ext_1 = cb.alloc_n_cells(word_cap);

        let headers_value = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);
        let headers_value_mask = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);
        let headers_value_addr_ext_0 = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);
        let headers_value_addr_ext_1 = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);

        let new_headers_value = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);

        Self {
            headers_count,
            value_index,
            offset_pow2,

            ref_val,
            ref_val_mask,
            ref_val_addr_ext_mask_0,
            ref_val_addr_ext_mask_1,

            vec_frame_index_or_global_address,
            vec_locals_index_or_global_sd_idx,

            value,
            value_mask,
            value_addr_ext_0,
            value_addr_ext_1,

            new_value_addr_ext_0,
            new_value_addr_ext_1,

            headers_value,
            headers_value_mask,
            headers_value_addr_ext_0,
            headers_value_addr_ext_1,

            new_headers_value,
        }
    }
}
