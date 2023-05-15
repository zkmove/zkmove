// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{
    LookupBytecode, RefVal, Word, WordWithExt,
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
pub struct VecPushBack<F: FieldExt> {
    value: Vec<Cell<F>>,
    value_mask: Vec<Cell<F>>,
    value_addr_ext_0: Vec<Cell<F>>,
    value_addr_ext_1: Vec<Cell<F>>,

    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,

    vec_frame_index: Cell<F>,
    vec_locals_index: Cell<F>,
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
        // for instruction VecPushBack, there are 4 pipeline stages here:
        // 1. read value from stack. [gc, word_element_num]
        // 2. read vec ref from stack. [gc+word_element_num, DEPTH_OF_ADDRESS_PATH]
        // 3. write value into container (locals or global).
        // [gc + word_element_num + DEPTH_OF_ADDRESS_PATH, word_element_num]
        // 4. write current and parent headers (flattened element num, length).
        // [gc + word_element_num * 2 + DEPTH_OF_ADDRESS_PATH, headers_count]

        let cond = cells.conditions[Opcode::VecPushBack.index()]
            .expression
            .clone();

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 2.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let headers_count = cells.auxiliary_2.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2.expr() * word_element_num.clone()
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
                read,
                cond.clone() * (1.expr() - self.value_mask[i].expression.clone()),
            ));

            // write value into container
            let write = RWLookup::locals_write(
                cells.gc.expression.clone()
                    + word_element_num.clone()
                    + depth_of_addr_path_expr.clone()
                    + (i as u64).expr(),
                self.vec_frame_index.expression.clone(),
                self.vec_locals_index.expression.clone(),
                self.new_value_addr_ext_0[i].expression.clone(),
                self.new_value_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
                0.expr(),
            );
            lookups.rw_lookups.push((
                write,
                cond.clone() * (1.expr() - self.value_mask[i].expression.clone()),
            ));
        }

        // read reference from stack
        for (i, item) in self.ref_val.iter().enumerate().take(DEPTH_OF_ADDRESS_PATH) {
            lookups.rw_lookups.push((
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + word_element_num.clone() + (i as u64).expr(),
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
            + word_element_num.clone() * 2.expr()
            + depth_of_addr_path_expr.clone();
        for (i, item) in self
            .headers_value
            .iter()
            .enumerate()
            .take(DEPTH_OF_ADDRESS_PATH - 2)
        {
            let read = RWLookup::locals_read(
                gc_offset.clone() + (i as u64).expr(),
                self.vec_frame_index.expression.clone(),
                self.vec_locals_index.expression.clone(),
                self.headers_value_addr_ext_0[i].expression.clone(),
                self.headers_value_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
                self.headers_value_ext[i].expression.clone(),
            );
            lookups.rw_lookups.push((
                read,
                cond.clone() * (1.expr() - self.headers_value_mask[i].expression.clone()),
            ));

            let write = RWLookup::locals_write(
                gc_offset.clone() + headers_count.clone() + (i as u64).expr(),
                self.vec_frame_index.expression.clone(),
                self.vec_locals_index.expression.clone(),
                self.headers_value_addr_ext_0[i].expression.clone(),
                self.headers_value_addr_ext_1[i].expression.clone(),
                self.new_headers_value[i].expression.clone(),
                self.new_headers_value_ext[i].expression.clone(),
            );
            lookups.rw_lookups.push((
                write,
                cond.clone() * (1.expr() - self.headers_value_mask[i].expression.clone()),
            ));
        }

        // Constrains the value to be pushed to the vector referenced by vec_ref.
        let mut constraint = cond.clone()
            * (self.ref_val[0].expression.clone() - self.vec_frame_index.expression.clone())
            * (1.expr() - self.ref_val_mask[0].expression.clone());
        cb.add_constraint("read_ref_eq_0", constraint);
        //todo: cells.ref_val[0] equal to account_address(Global)
        constraint = cond.clone()
            * (self.ref_val[1].expression.clone() - self.vec_locals_index.expression.clone())
            * (1.expr() - self.ref_val_mask[1].expression.clone());
        cb.add_constraint("read_ref_eq_1", constraint);
        //todo: cells.ref_val[1] equal to sd_index(Global)
        constraint = cond.clone()
            * (self.ref_val[2].expression.clone()
                - self.new_value_addr_ext_0[0].expression.clone())
            * (1.expr() - self.ref_val_mask[2].expression.clone());
        cb.add_constraint("read_ref_eq_2", constraint);
        constraint = cond.clone()
            * (self.ref_val[3].expression.clone()
                - self.new_value_addr_ext_1[0].expression.clone())
            * (1.expr() - self.ref_val_mask[3].expression.clone());
        cb.add_constraint("read_ref_eq_3", constraint);

        // Constrains the address of headers must be part of the vector's address path.
        // For example, if the vector has address path [3,1,2,1], the header's address will
        // be: [3,1,0,0],[3,1,2,0],[3,1,2,1]
        //
        // Skip header[0], it's already constrained by the above lookup
        for i in 1..(DEPTH_OF_ADDRESS_PATH - 2) {
            // header[i]'s frame_index must equal to ref_val[0],
            // already constrained by the above lookup

            // header[i]'s locals_index must equal to ref_val[1],
            // already constrained by the above lookup

            // header[i]'s addr_ext_0 must equal to ref_val[2],
            let constraint = cond.clone()
                * (1.expr() - self.headers_value_mask[i].expression.clone())
                * (self.headers_value_addr_ext_0[i].expression.clone()
                    - self.ref_val[2].expression.clone());
            cb.add_constraint("check header addr_ext_0", constraint);

            // TODO:
            // header[i]'s addr_ext_1 must equal to ref_val[3],
            // the current impl only support two layers nesting
            // add constraints when to support configurable layers
        }

        // Constrains the headers are correctly updated.
        for i in 0..(DEPTH_OF_ADDRESS_PATH - 2) {
            let constraint = cond.clone()
                * (1.expr() - self.headers_value_mask[i].expression.clone())
                * (self.headers_value[i].expression.clone() + word_element_num.clone()
                    - self.new_headers_value[i].expression.clone());
            cb.add_constraint("header_val_increased", constraint);

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
        let si = step.auxiliary_1.as_ref().ok_or_else(|| {
            error!("signature index is None");
            Error::Synthesis
        })?;
        cells.auxiliary_1.assign(region, offset, si.value())?;

        // assign the value
        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;
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
            word_element_num,
        )?;

        // assign ref_word_element_num
        let ref_word_element_num = step.auxiliary_4.as_ref().ok_or_else(|| {
            error!("ref_word_element_num is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_4
            .assign(region, offset, ref_word_element_num.value())?;
        let ref_word_element_count = ref_word_element_num
            .value()
            .ok_or_else(|| {
                error!("failed to get ref_word_element_num");
                Error::Synthesis
            })?
            .get_lower_128() as usize;

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
            step.gc + word_element_num,
            ref_word_element_count,
        )?;

        // assign the pushed-back value
        let op = rw_operations
            .0
            .get(step.gc + word_element_num + DEPTH_OF_ADDRESS_PATH)
            .ok_or(Error::Synthesis)?;

        self.vec_frame_index
            .assign(region, offset, Some(F::from(op.frame_index() as u64)))?;
        self.vec_locals_index
            .assign(region, offset, Some(F::from(op.address() as u64)))?;

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
            step.gc + word_element_num + DEPTH_OF_ADDRESS_PATH,
            word_element_num,
        )?;

        // assign container headers
        let headers_num = step.auxiliary_2.as_ref().ok_or_else(|| {
            error!("headers_num is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_2
            .assign(region, offset, headers_num.value())?;
        let headers_count = headers_num
            .value()
            .ok_or_else(|| {
                error!("failed to get headers_count");
                Error::Synthesis
            })?
            .get_lower_128() as usize;

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
            step.gc + word_element_num * 2 + DEPTH_OF_ADDRESS_PATH,
            headers_count,
            DEPTH_OF_ADDRESS_PATH - 2,
        )?;

        let new_headers_op_idx =
            step.gc + word_element_num * 2 + DEPTH_OF_ADDRESS_PATH + headers_count;
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
        let value = cb.alloc_n_cells(WORD_CAPACITY);
        let value_mask = cb.alloc_n_cells(WORD_CAPACITY);
        let value_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let value_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);

        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);

        let vec_frame_index = cb.alloc_cell();
        let vec_locals_index = cb.alloc_cell();
        let new_value_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let new_value_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);

        // todo: pass max_container_depth as circuit configuration;
        let headers_value = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH - 2);
        let headers_value_ext = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH - 2);
        let headers_value_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH - 2);
        let headers_value_addr_ext_0 = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH - 2);
        let headers_value_addr_ext_1 = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH - 2);

        let new_headers_value = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH - 2);
        let new_headers_value_ext = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH - 2);

        Self {
            value,
            value_mask,
            value_addr_ext_0,
            value_addr_ext_1,

            ref_val,
            ref_val_mask,

            vec_frame_index,
            vec_locals_index,
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
