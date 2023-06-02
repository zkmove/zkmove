// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{
    AddrExt, LookupBytecode, RefVal, Word, WordWithExt,
};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::{MAX_ADDRESS_EXT_LENGTH, WORD_CAPACITY};
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::value::{DEPTH_OF_ADDRESS_PATH, DEPTH_OF_LOCATION_PATH};

#[derive(Clone, Debug)]
pub struct VecPushBack<F: FieldExt> {
    headers_count: Cell<F>,
    value_index: Cell<F>,
    offset_pow2: Cell<F>,

    value: Vec<Cell<F>>,
    value_mask: Vec<Cell<F>>,
    value_addr_ext_0: Vec<Cell<F>>,
    value_addr_ext_1: Vec<Cell<F>>,

    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,
    ref_val_addr_ext_mask_0: Vec<Cell<F>>,
    ref_val_addr_ext_mask_1: Vec<Cell<F>>,

    vec_frame_index_or_global_address: Cell<F>,
    vec_locals_index_or_global_sd_idx: Cell<F>,
    new_value_addr_ext_0: Vec<Cell<F>>,
    new_value_addr_ext_1: Vec<Cell<F>>,

    headers_value: Vec<Cell<F>>,
    headers_value_ext: Vec<Cell<F>>,
    headers_value_mask: Vec<Cell<F>>,
    headers_value_addr_ext_0: Vec<Cell<F>>,
    headers_value_addr_ext_1: Vec<Cell<F>>,

    new_headers_value: Vec<Cell<F>>,
    new_headers_value_ext: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for VecPushBack<F> {
    const NAME: &'static str = "VEC_PUSH_BACK";

    const OPCODE: Opcode = Opcode::VecPushBack;
    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        // for instruction VecPushBack, there are 4 steps here:
        // 1. read value from stack. [gc, value_flattened_len]
        // 2. read vec ref from stack. [gc+value_flattened_len, DEPTH_OF_ADDRESS_PATH]
        // 3. write value into container (locals or global).
        // [gc + value_flattened_len + DEPTH_OF_ADDRESS_PATH, value_flattened_len]
        // 4. update current and parent headers (flattened length, length).
        // [gc + value_flattened_len * 2 + DEPTH_OF_ADDRESS_PATH, headers_count * 2]

        let cond = cells.opcode_selector([Self::OPCODE]);

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 2.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let value_flattened_len = cells.auxiliary_3.expression.clone();
        let ref_val_flattened_len = cells.auxiliary_4.expression.clone();
        let headers_count = self.headers_count.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2.expr() * value_flattened_len.clone()
            + depth_of_addr_path_expr.clone()
            + 2.expr() * headers_count.clone();
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

        let is_global = cells.auxiliary_5.expression.clone();
        for (i, item) in self.value.iter().enumerate().take(WORD_CAPACITY) {
            // read value from stack
            let read = RWLookup::stack_pop(
                cells.gc.expression.clone() + (i as u64).expr(),
                cells.stack_size.expression.clone(),
                self.value_addr_ext_0[i].expression.clone(),
                self.value_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
                0.expr(), //fixme, value_ext may not be 0.
            );
            lookups.rw_lookups.push((
                "vec_push_back(read value)",
                read,
                cond.clone() * (1.expr() - self.value_mask[i].expression.clone()),
            ));

            // write value into container
            let locals_write = RWLookup::locals_write(
                cells.gc.expression.clone()
                    + value_flattened_len.clone()
                    + depth_of_addr_path_expr.clone()
                    + (i as u64).expr(),
                self.vec_frame_index_or_global_address.expression.clone(),
                self.vec_locals_index_or_global_sd_idx.expression.clone(),
                self.new_value_addr_ext_0[i].expression.clone(),
                self.new_value_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
                0.expr(),
            );
            lookups.rw_lookups.push((
                "vec_push_back(write value)",
                locals_write,
                cond.clone()
                    * (1.expr() - self.value_mask[i].expression.clone())
                    * (1.expr() - is_global.clone()),
            ));

            let global_write = RWLookup::global_write(
                cells.gc.expression.clone()
                    + value_flattened_len.clone()
                    + depth_of_addr_path_expr.clone()
                    + (i as u64).expr(),
                self.vec_frame_index_or_global_address.expression.clone(),
                item.expression.clone(),
                0.expr(),
                self.vec_locals_index_or_global_sd_idx.expression.clone(),
                self.new_value_addr_ext_0[i].expression.clone(),
                self.new_value_addr_ext_1[i].expression.clone(),
            );
            lookups.rw_lookups.push((
                "vec_push_back(write value)",
                global_write,
                cond.clone()
                    * (1.expr() - self.value_mask[i].expression.clone())
                    * is_global.clone(),
            ));
        }

        // read reference from stack
        for (i, item) in self.ref_val.iter().enumerate().take(DEPTH_OF_ADDRESS_PATH) {
            lookups.rw_lookups.push((
                "vec_push_back(read ref)",
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + value_flattened_len.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                    0.expr(),
                ),
                cond.clone() * (1.expr() - self.ref_val_mask[i].expression.clone()),
            ));
        }

        // read the old value from headers and write the new value to the headers
        let gc_offset = cells.gc.expression.clone()
            + value_flattened_len.clone() * 2.expr()
            + depth_of_addr_path_expr;
        for (i, item) in self
            .headers_value
            .iter()
            .enumerate()
            .take(MAX_ADDRESS_EXT_LENGTH)
        {
            let locals_read = RWLookup::locals_read(
                gc_offset.clone() + (i as u64).expr(),
                self.vec_frame_index_or_global_address.expression.clone(),
                self.vec_locals_index_or_global_sd_idx.expression.clone(),
                self.headers_value_addr_ext_0[i].expression.clone(),
                self.headers_value_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
                self.headers_value_ext[i].expression.clone(),
            );
            lookups.rw_lookups.push((
                "vec_push_back(read headers)",
                locals_read,
                cond.clone()
                    * (1.expr() - self.headers_value_mask[i].expression.clone())
                    * (1.expr() - is_global.clone()),
            ));

            let global_read = RWLookup::global_read(
                gc_offset.clone() + (i as u64).expr(),
                self.vec_frame_index_or_global_address.expression.clone(),
                item.expression.clone(),
                self.headers_value_ext[i].expression.clone(),
                self.vec_locals_index_or_global_sd_idx.expression.clone(),
                self.headers_value_addr_ext_0[i].expression.clone(),
                self.headers_value_addr_ext_1[i].expression.clone(),
            );
            lookups.rw_lookups.push((
                "vec_push_back(read headers)",
                global_read,
                cond.clone()
                    * (1.expr() - self.headers_value_mask[i].expression.clone())
                    * is_global.clone(),
            ));

            let locals_write = RWLookup::locals_write(
                gc_offset.clone() + headers_count.clone() + (i as u64).expr(),
                self.vec_frame_index_or_global_address.expression.clone(),
                self.vec_locals_index_or_global_sd_idx.expression.clone(),
                self.headers_value_addr_ext_0[i].expression.clone(),
                self.headers_value_addr_ext_1[i].expression.clone(),
                self.new_headers_value[i].expression.clone(),
                self.new_headers_value_ext[i].expression.clone(),
            );
            lookups.rw_lookups.push((
                "vec_push_back(write headers)",
                locals_write,
                cond.clone()
                    * (1.expr() - self.headers_value_mask[i].expression.clone())
                    * (1.expr() - is_global.clone()),
            ));

            let global_write = RWLookup::global_write(
                gc_offset.clone() + headers_count.clone() + (i as u64).expr(),
                self.vec_frame_index_or_global_address.expression.clone(),
                self.new_headers_value[i].expression.clone(),
                self.new_headers_value_ext[i].expression.clone(),
                self.vec_locals_index_or_global_sd_idx.expression.clone(),
                self.headers_value_addr_ext_0[i].expression.clone(),
                self.headers_value_addr_ext_1[i].expression.clone(),
            );
            lookups.rw_lookups.push((
                "vec_push_back(write headers)",
                global_write,
                cond.clone()
                    * (1.expr() - self.headers_value_mask[i].expression.clone())
                    * is_global.clone(),
            ));
        }

        // Constrains the value to be pushed to the vector referenced by vec_ref.
        let mut constraint = cond.clone()
            * (self.ref_val[0].expression.clone()
                - self.vec_frame_index_or_global_address.expression.clone())
            * (1.expr() - self.ref_val_mask[0].expression.clone());
        cb.add_constraint("read_ref_eq_0", constraint);
        constraint = cond.clone()
            * (self.ref_val[1].expression.clone()
                - self.vec_locals_index_or_global_sd_idx.expression.clone())
            * (1.expr() - self.ref_val_mask[1].expression.clone());
        cb.add_constraint("read_ref_eq_1", constraint);

        // addr_ext comparation between ref_val and indexed_ref_val
        // field_offset is pushed into the last element of indexed_ref_val,
        // and it's larger than the real offset by 1
        let offset = &self.value_index; // field_offset
        let constraint = cond.clone()
            * (self.ref_val[2].expression.clone()
                + (offset.expression.clone() + 1.expr()) * self.offset_pow2.expression.clone()
                - self.new_value_addr_ext_0[0].expression.clone())
            * (1.expr() - self.ref_val_mask[2].expression.clone());
        cb.add_constraint("field_offset check with ref_val[2]", constraint);

        // Constrains the address of headers must be part of the vector's address path.
        // For example, if the vector has address path [3,1,2,1], the header's address will
        // be: [3,1,0,0],[3,1,2,0],[3,1,2,1]
        //
        // header[i]'s frame_index or global address must equal to ref_val[0],
        // header[i]'s locals_index or global sd_index must equal to ref_val[1],
        // already constrained by the above lookup
        for i in 0..(MAX_ADDRESS_EXT_LENGTH) {
            // header[i]'s addr_ext_0 must equal to ref_val[2],
            let constraint = cond.clone()
                * (self.ref_val_addr_ext_mask_0[i].expression.clone())
                * (1.expr() - self.ref_val_addr_ext_mask_1[i].expression.clone())
                * (self.headers_value_addr_ext_0[i].expression.clone()
                    - self.ref_val[2].expression.clone());
            cb.add_constraint("check header addr_ext_0", constraint);
        }

        // constraint on addr_ext_mask_0 and addr_ext_mask_1
        // skip DEPTH_OF_LOCATION_PATH bits tophead.
        AddrExt::constrain_mask_n(
            &self.ref_val_addr_ext_mask_0,
            &self.ref_val_addr_ext_mask_1,
            ref_val_flattened_len - (DEPTH_OF_LOCATION_PATH as u64).expr(),
            (MAX_ADDRESS_EXT_LENGTH as u64).expr(),
            cb,
            cond.clone(),
        );

        // Constrains the headers are correctly updated.
        for i in 0..(MAX_ADDRESS_EXT_LENGTH) {
            // flattened len. include header
            let constraint = cond.clone()
                * (1.expr() - self.headers_value_mask[i].expression.clone())
                * (self.headers_value[i].expression.clone() + value_flattened_len.clone()
                    - self.new_headers_value[i].expression.clone());
            cb.add_constraint("header_val_increased", constraint);

            // elements len
            let constraint = cond.clone()
                * (headers_count.clone() - (i as u64 + 1).expr()) //exclude the current header
                * (1.expr() - self.headers_value_mask[i].expression.clone())
                * (self.headers_value_ext[i].expression.clone()
                    - self.new_headers_value_ext[i].expression.clone());
            cb.add_constraint("header_val_ext_unchanged", constraint);
        }

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::VecPushBack,
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

        let value = Word {
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
            &value,
            step.gc,
            value_flattened_len,
        )?;

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
            step.gc + value_flattened_len,
            ref_val_flattened_len,
        )?;

        // assign the pushed-back value
        let index = step.gc + value_flattened_len + DEPTH_OF_ADDRESS_PATH;
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

        let push_back = Word {
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
            &push_back,
            index,
            value_flattened_len,
        )?;

        // assign bytes mask
        // skip DEPTH_OF_LOCATION_PATH bits tophead.
        let n = ref_val_flattened_len as usize - DEPTH_OF_LOCATION_PATH;
        let mask_a = &self.ref_val_addr_ext_mask_0;
        let mask_b = &self.ref_val_addr_ext_mask_1;
        AddrExt::assign_byte_n_mask(region, offset, mask_a, mask_b, n)?;

        let headers = WordWithExt {
            word: self.headers_value.clone(),
            word_ext: self.headers_value_ext.clone(),
            word_mask: self.headers_value_mask.clone(),
            word_addr_ext_0: self.headers_value_addr_ext_0.clone(),
            word_addr_ext_1: self.headers_value_addr_ext_1.clone(),
        };
        Word::assign_word_with_ext(
            region,
            offset,
            rw_operations,
            &headers,
            step.gc + value_flattened_len * 2 + DEPTH_OF_ADDRESS_PATH,
            headers_count,
            MAX_ADDRESS_EXT_LENGTH,
        )?;

        let new_headers_op_idx =
            step.gc + value_flattened_len * 2 + DEPTH_OF_ADDRESS_PATH + headers_count;
        for i in 0..headers_count {
            let op = rw_operations
                .0
                .get(new_headers_op_idx + i)
                .ok_or(Error::Synthesis)?;
            self.new_headers_value[i].assign(region, offset, op.value().value())?;
            self.new_headers_value_ext[i].assign(region, offset, op.value_ext().value())?;
        }

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let headers_count = cb.alloc_cell();
        let value_index = cb.alloc_cell();
        let offset_pow2 = cb.alloc_cell();

        let value = cb.alloc_n_cells(WORD_CAPACITY);
        let value_mask = cb.alloc_n_cells(WORD_CAPACITY);
        let value_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let value_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);

        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_addr_ext_mask_0 = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);
        let ref_val_addr_ext_mask_1 = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);

        let vec_frame_index_or_global_address = cb.alloc_cell();
        let vec_locals_index_or_global_sd_idx = cb.alloc_cell();
        let new_value_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let new_value_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);

        let headers_value = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);
        let headers_value_ext = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);
        let headers_value_mask = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);
        let headers_value_addr_ext_0 = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);
        let headers_value_addr_ext_1 = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);

        let new_headers_value = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);
        let new_headers_value_ext = cb.alloc_n_cells(MAX_ADDRESS_EXT_LENGTH);
        Self {
            headers_count,
            value_index,
            offset_pow2,

            value,
            value_mask,
            value_addr_ext_0,
            value_addr_ext_1,

            ref_val,
            ref_val_mask,
            ref_val_addr_ext_mask_0,
            ref_val_addr_ext_mask_1,

            vec_frame_index_or_global_address,
            vec_locals_index_or_global_sd_idx,
            new_value_addr_ext_0,
            new_value_addr_ext_1,

            headers_value,
            headers_value_ext,
            headers_value_mask,
            headers_value_addr_ext_0,
            headers_value_addr_ext_1,

            new_headers_value,
            new_headers_value_ext,
        }
    }
}
