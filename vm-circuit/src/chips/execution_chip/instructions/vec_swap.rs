// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, RefVal, Word};
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
use movelang::value::DEPTH_OF_ADDRESS_PATH;

#[derive(Clone, Debug)]
pub struct VecSwap<F: FieldExt> {
    idx_a: Cell<F>,
    idx_b: Cell<F>,

    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,

    vec_frame_index: Cell<F>,
    vec_locals_index: Cell<F>,

    value_a: Vec<Cell<F>>,
    value_a_mask: Vec<Cell<F>>,
    value_a_addr_ext_0: Vec<Cell<F>>,
    value_a_addr_ext_1: Vec<Cell<F>>,

    value_b: Vec<Cell<F>>,
    value_b_mask: Vec<Cell<F>>,
    value_b_addr_ext_0: Vec<Cell<F>>,
    value_b_addr_ext_1: Vec<Cell<F>>,

    ref_value_a_mask: Vec<Cell<F>>,
    ref_value_b_mask: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for VecSwap<F> {
    const NAME: &'static str = "VEC_SWAP";

    const OPCODE: Opcode = Opcode::VecSwap;
    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        // for instruction VecSwap, there are 4 pipeline stages here:
        // 1. read idx_a, idx_b from stack [gc, 2]
        // 2. read vec ref from stack. [gc + 2, DEPTH_OF_ADDRESS_PATH]
        // 3. read value_a from vec (in locals or global).
        // [gc + 2 + DEPTH_OF_ADDRESS_PATH, word_a_element_num]
        // 4. read value_b from vec (in locals or global).
        // [gc + 2 + DEPTH_OF_ADDRESS_PATH + word_a_element_num, word_b_element_num]
        // 5. read value_a to vec (in locals or global).
        // [gc + 2 + DEPTH_OF_ADDRESS_PATH + word_a_element_num + word_b_element_num,
        // word_a_element_num]
        // 6. read value_b to vec (in locals or global).
        // [gc + 2 + DEPTH_OF_ADDRESS_PATH + 2 * word_a_element_num + word_b_element_num,
        // word_b_element_num]

        let cond = cells.conditions[Opcode::VecSwap.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 3.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_a_element_num = cells.auxiliary_2.expression.clone();
        let word_b_element_num = cells.auxiliary_3.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2.expr()
            + depth_of_addr_path_expr.clone()
            + word_a_element_num.clone() * 2.expr()
            + word_b_element_num.clone() * 2.expr();
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

        lookups.rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                self.idx_b.expression.clone(),
                0.expr(),
            ),
            cond.clone(),
        ));
        lookups.rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                0.expr(),
                0.expr(),
                self.idx_a.expression.clone(),
                0.expr(),
            ),
            cond.clone(),
        ));

        // read reference from stack
        for (i, item) in self.ref_val.iter().enumerate().take(DEPTH_OF_ADDRESS_PATH) {
            lookups.rw_lookups.push((
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + 2.expr() + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 2.expr(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                    0.expr(),
                ),
                cond.clone() * (1.expr() - self.ref_val_mask[i].expression.clone()),
            ));
        }

        for (i, item) in self.value_a.iter().enumerate().take(WORD_CAPACITY) {
            // read value_a
            let read = RWLookup::locals_read(
                cells.gc.expression.clone()
                    + 2.expr()
                    + depth_of_addr_path_expr.clone()
                    + (i as u64).expr(),
                self.vec_frame_index.expression.clone(),
                self.vec_locals_index.expression.clone(),
                self.value_a_addr_ext_0[i].expression.clone(),
                self.value_a_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
                0.expr(),
            );
            lookups.rw_lookups.push((
                read,
                cond.clone() * (1.expr() - self.value_a_mask[i].expression.clone()),
            ));

            // write value_a
            let write = RWLookup::locals_write(
                cells.gc.expression.clone()
                    + 2.expr()
                    + depth_of_addr_path_expr.clone()
                    + word_a_element_num.clone()
                    + word_b_element_num.clone()
                    + (i as u64).expr(),
                self.vec_frame_index.expression.clone(),
                self.vec_locals_index.expression.clone(),
                self.value_b_addr_ext_0[i].expression.clone(),
                self.value_b_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
                0.expr(), //fixme, value_ext may not be 0.
            );
            lookups.rw_lookups.push((
                write,
                cond.clone() * (1.expr() - self.value_a_mask[i].expression.clone()),
            ));
        }

        for (i, item) in self.value_b.iter().enumerate().take(WORD_CAPACITY) {
            // read value_b
            let read = RWLookup::locals_read(
                cells.gc.expression.clone()
                    + 2.expr()
                    + depth_of_addr_path_expr.clone()
                    + word_a_element_num.clone()
                    + (i as u64).expr(),
                self.vec_frame_index.expression.clone(),
                self.vec_locals_index.expression.clone(),
                self.value_b_addr_ext_0[i].expression.clone(),
                self.value_b_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
                0.expr(),
            );
            lookups.rw_lookups.push((
                read,
                cond.clone() * (1.expr() - self.value_b_mask[i].expression.clone()),
            ));

            // write value_b
            let write = RWLookup::locals_write(
                cells.gc.expression.clone()
                    + 2.expr()
                    + depth_of_addr_path_expr.clone()
                    + 2.expr() * word_a_element_num.clone()
                    + word_b_element_num.clone()
                    + (i as u64).expr(),
                self.vec_frame_index.expression.clone(),
                self.vec_locals_index.expression.clone(),
                self.value_a_addr_ext_0[i].expression.clone(),
                self.value_a_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
                0.expr(), //fixme, value_ext may not be 0.
            );
            lookups.rw_lookups.push((
                write,
                cond.clone() * (1.expr() - self.value_b_mask[i].expression.clone()),
            ));
        }

        // Constrains ref_val[0] == vec_frame_index.
        let mut constraint = cond.clone()
            * (self.ref_val[0].expression.clone() - self.vec_frame_index.expression.clone())
            * (1.expr() - self.ref_val_mask[0].expression.clone());
        cb.add_constraint("ref_check_0", constraint);
        //todo: cells.ref_val[0] equal to account_address(Global)

        // Constrains ref_val[1] == vec_locals_index.
        constraint = cond.clone()
            * (self.ref_val[1].expression.clone() - self.vec_locals_index.expression.clone())
            * (1.expr() - self.ref_val_mask[1].expression.clone());
        cb.add_constraint("ref_check_1", constraint);
        //todo: cells.ref_val[1] equal to sd_index(Global)

        // Constrains ref_val[2] == value_a_addr_ext_0[0] == value_b_addr_ext_0[0].
        constraint = cond.clone()
            * (self.ref_val[2].expression.clone() - self.value_a_addr_ext_0[0].expression.clone())
            * (1.expr() - self.ref_val_mask[2].expression.clone());
        cb.add_constraint("ref_check_2", constraint);
        constraint = cond.clone()
            * (self.ref_val[2].expression.clone() - self.value_b_addr_ext_0[0].expression.clone())
            * (1.expr() - self.ref_val_mask[2].expression.clone());
        cb.add_constraint("ref_check_2", constraint);

        // Constrains ref_val[3] == value_a_addr_ext_1[0] == value_b_addr_ext_1[0].
        constraint = cond.clone()
            * (self.ref_val[3].expression.clone() - self.value_a_addr_ext_1[0].expression.clone())
            * (1.expr() - self.ref_val_mask[3].expression.clone());
        cb.add_constraint("ref_check_3", constraint);
        constraint = cond.clone()
            * (self.ref_val[3].expression.clone() - self.value_b_addr_ext_1[0].expression.clone())
            * (1.expr() - self.ref_val_mask[3].expression.clone());
        cb.add_constraint("ref_check_3", constraint);

        // value_a is read from idx_a, value_b is read from idx_b
        // idx_a + 1 == value_a_address_path[last]
        // idx_b + 1 == value_b_address_path[last]
        // counting the header, it's 1 larger than the real offset
        for i in 0..WORD_CAPACITY {
            constraint = cond.clone()
                * (self.idx_a.expression.clone() + 1.expr()
                    - self.value_a_addr_ext_0[i].expression.clone())
                * self.ref_val_mask[2].expression.clone()
                * (1.expr() - self.ref_value_a_mask[2].expression.clone())
                * (1.expr() - self.value_a_mask[i].expression.clone());
            cb.add_constraint("idx_a_check", constraint);

            constraint = cond.clone()
                * (self.idx_a.expression.clone() + 1.expr()
                    - self.value_a_addr_ext_1[i].expression.clone())
                * self.ref_val_mask[3].expression.clone()
                * (1.expr() - self.ref_value_a_mask[3].expression.clone())
                * (1.expr() - self.value_a_mask[i].expression.clone());
            cb.add_constraint("idx_a_check", constraint);

            constraint = cond.clone()
                * (self.idx_b.expression.clone() + 1.expr()
                    - self.value_b_addr_ext_0[i].expression.clone())
                * self.ref_val_mask[2].expression.clone()
                * (1.expr() - self.ref_value_b_mask[2].expression.clone())
                * (1.expr() - self.value_b_mask[i].expression.clone());
            cb.add_constraint("idx_b_check", constraint);

            constraint = cond.clone()
                * (self.idx_b.expression.clone() + 1.expr()
                    - self.value_b_addr_ext_1[i].expression.clone())
                * self.ref_val_mask[3].expression.clone()
                * (1.expr() - self.ref_value_b_mask[3].expression.clone())
                * (1.expr() - self.value_b_mask[i].expression.clone());
            cb.add_constraint("idx_b_check", constraint);
        }

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::VecSwap,
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
        let _si = Word::assign_auxiliary_1(region, offset, step, cells)?;
        let word_a_element_num =
            Word::assign_auxiliary_2(region, offset, step, cells)?.get_lower_128() as usize;
        let word_b_element_num =
            Word::assign_auxiliary_3(region, offset, step, cells)?.get_lower_128() as usize;
        let ref_word_element_count =
            Word::assign_auxiliary_4(region, offset, step, cells)?.get_lower_128() as usize;

        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        self.idx_b.assign(region, offset, op.value().value())?;
        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
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
            step.gc + 2,
            ref_word_element_count,
        )?;

        let op = rw_operations
            .0
            .get(step.gc + 2 + DEPTH_OF_ADDRESS_PATH)
            .ok_or(Error::Synthesis)?;

        self.vec_frame_index
            .assign(region, offset, Some(F::from(op.frame_index() as u64)))?;
        self.vec_locals_index
            .assign(region, offset, Some(F::from(op.address() as u64)))?;

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
            step.gc + 2 + DEPTH_OF_ADDRESS_PATH,
            word_a_element_num,
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
            step.gc + 2 + DEPTH_OF_ADDRESS_PATH + word_a_element_num,
            word_b_element_num,
        )?;

        // assign ref_value_a_mask and ref_value_b_mask
        for i in 0..(ref_word_element_count + 1) {
            self.ref_value_a_mask[i].assign(region, offset, Some(F::zero()))?;
            self.ref_value_b_mask[i].assign(region, offset, Some(F::zero()))?;
        }
        for i in (ref_word_element_count + 1)..DEPTH_OF_ADDRESS_PATH {
            self.ref_value_a_mask[i].assign(region, offset, Some(F::one()))?;
            self.ref_value_b_mask[i].assign(region, offset, Some(F::one()))?;
        }

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let idx_a = cb.alloc_cell();
        let idx_b = cb.alloc_cell();

        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);

        let vec_frame_index = cb.alloc_cell();
        let vec_locals_index = cb.alloc_cell();

        let value_a = cb.alloc_n_cells(WORD_CAPACITY);
        let value_a_mask = cb.alloc_n_cells(WORD_CAPACITY);
        let value_a_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let value_a_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);

        let value_b = cb.alloc_n_cells(WORD_CAPACITY);
        let value_b_mask = cb.alloc_n_cells(WORD_CAPACITY);
        let value_b_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let value_b_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);

        let ref_value_a_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_value_b_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);

        Self {
            idx_a,
            idx_b,

            ref_val,
            ref_val_mask,

            vec_frame_index,
            vec_locals_index,

            value_a,
            value_a_mask,
            value_a_addr_ext_0,
            value_a_addr_ext_1,

            value_b,
            value_b_mask,
            value_b_addr_ext_0,
            value_b_addr_ext_1,

            ref_value_a_mask,
            ref_value_b_mask,
        }
    }
}
