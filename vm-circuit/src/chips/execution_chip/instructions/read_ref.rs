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
use logger::prelude::*;
use movelang::word::ValueHeader;
use movelang::word::LEN_OF_REFERENCE_VALUE;

#[derive(Clone, Debug)]
pub struct ReadRef<F: FieldExt> {
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,
    word_b: Vec<Cell<F>>,
    word_b_mask: Vec<Cell<F>>,
    word_b_addr_ext_0: Vec<Cell<F>>,
    word_b_addr_ext_1: Vec<Cell<F>>,
    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for ReadRef<F> {
    const NAME: &'static str = "READREF";

    const OPCODE: Opcode = Opcode::ReadRef;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // for instruction readref, there are 3 pipeline stages here:
        // 1. read reference from stack. [gc, LEN_OF_REFERENCE_VALUE]
        // 2. read value from lobals or global. [gc+LEN_OF_REFERENCE_VALUE, word_element_num]
        // 3. store value into stack. [gc+LEN_OF_REFERENCE_VALUE+word_element_num, word_element_num]

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();

        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + (LEN_OF_REFERENCE_VALUE as u64).expr()
            + 2.expr() * word_element_num.clone();
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

        for (i, item) in self.ref_val.iter().enumerate().take(LEN_OF_REFERENCE_VALUE) {
            cb.add_lookup(
                "read_ref(stack pop)",
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                ),
            );
        }

        let is_global = cells.auxiliary_5.expression.clone();
        for (i, item) in self.word_b.iter().enumerate() {
            cb.condition(1.expr() - self.word_a_mask[i].expression.clone(), |cb| {
                // locals read or global read
                let read = RWLookup::locals_read(
                    cells.gc.expression.clone()
                        + (LEN_OF_REFERENCE_VALUE as u64).expr()
                        + (i as u64).expr(),
                    cells.auxiliary_2.expression.clone(), // frame_index
                    cells.locals_index.expression.clone(), // index
                    self.word_a_addr_ext_0[i].expression.clone(),
                    self.word_a_addr_ext_1[i].expression.clone(),
                    item.expression.clone(),
                );
                // locals read
                cb.condition(1.expr() - is_global.clone(), |cb| {
                    cb.add_lookup("read_ref(locals read)", read);
                });

                let read = RWLookup::global_read(
                    cells.gc.expression.clone()
                        + (LEN_OF_REFERENCE_VALUE as u64).expr()
                        + (i as u64).expr(),
                    cells.auxiliary_2.expression.clone(), // account_address
                    item.expression.clone(),
                    cells.auxiliary_4.expression.clone(), //sd_index
                    self.word_a_addr_ext_0[i].expression.clone(),
                    self.word_a_addr_ext_1[i].expression.clone(),
                );
                // global read
                cb.condition(is_global.clone(), |cb| {
                    cb.add_lookup("read_ref(global read)", read);
                });
            });

            // stack write
            let write = RWLookup::stack_push(
                cells.gc.expression.clone()
                    + (LEN_OF_REFERENCE_VALUE as u64).expr()
                    + word_element_num.clone()
                    + (i as u64).expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                self.word_b_addr_ext_0[i].expression.clone(),
                self.word_b_addr_ext_1[i].expression.clone(),
                item.expression.clone(),
            );
            cb.condition(1.expr() - self.word_b_mask[i].expression.clone(), |cb| {
                cb.add_lookup("read_ref(stack push)", write);
            });
        }

        // ref_val[0] equals to ref value header
        let constraint =
            self.ref_val[0].expression.clone() - ValueHeader::default_for_ref_val().expr();
        cb.add_constraint("read_ref_eq_0", constraint);

        // ref_val[1] equals to frame_index(Locals) or account_address(Global)
        let constraint = self.ref_val[1].expression.clone() - cells.auxiliary_2.expression.clone();
        cb.add_constraint("read_ref_eq_1", constraint);

        // ref_val[2] equel to local_index(Locals) or sd_index(Global)
        let constraint = (1.expr() - is_global.clone())
            * (self.ref_val[2].expression.clone() - cells.locals_index.expression.clone());
        cb.add_constraint("read_ref_eq_2", constraint);
        let constraint =
            is_global * (self.ref_val[2].expression.clone() - cells.auxiliary_4.expression.clone());
        cb.add_constraint("read_ref_eq_2", constraint);

        // ref_val[3] equal to word_a_addr_ext_0
        let constraint =
            self.ref_val[3].expression.clone() - self.word_a_addr_ext_0[0].expression.clone();
        cb.add_constraint("read_ref_eq_3", constraint);

        LookupBytecode::lookup_bytecode(cb, cells, Opcode::ReadRef, 0.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
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
            LEN_OF_REFERENCE_VALUE,
        )?;

        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;
        let word_a = Word {
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
            &word_a,
            step.gc + LEN_OF_REFERENCE_VALUE,
            word_element_num,
        )?;

        let word_b = Word {
            word: self.word_b.clone(),
            word_mask: self.word_b_mask.clone(),
            word_addr_ext_0: self.word_b_addr_ext_0.clone(),
            word_addr_ext_1: self.word_b_addr_ext_1.clone(),
        };
        Word::assign_word(
            region,
            offset,
            step,
            rw_operations,
            &word_b,
            step.gc + LEN_OF_REFERENCE_VALUE + word_element_num,
            word_element_num,
        )?;

        let is_global = step.auxiliary_5.as_ref().ok_or_else(|| {
            error!("auxiliary_5 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_5
            .assign(region, offset, is_global.value())?;

        if is_global.value() == Some(F::zero()) {
            // assign the frame_index of the frame we refer to
            let aux_value = step.auxiliary_2.as_ref().ok_or_else(|| {
                error!("auxiliary_2 is None");
                Error::Synthesis
            })?;
            cells
                .auxiliary_2
                .assign(region, offset, aux_value.value())?;
        } else {
            // assign the account address to auxiliary_2
            let address = step.auxiliary_2.as_ref().ok_or_else(|| {
                error!("auxiliary_2 is None");
                Error::Synthesis
            })?;
            cells.auxiliary_2.assign(region, offset, address.value())?;

            // assign the sd_index to auxiliary_4
            let sd_index = step.auxiliary_4.as_ref().ok_or_else(|| {
                error!("auxiliary_4 is None");
                Error::Synthesis
            })?;
            cells.auxiliary_4.assign(region, offset, sd_index.value())?;
        }
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let word_cap = word_capacity();

        // alloc cell
        let word_a = cb.alloc_n_cells(word_cap);
        let word_a_mask = cb.alloc_n_cells(word_cap);
        let word_a_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let word_a_addr_ext_1 = cb.alloc_n_cells(word_cap);
        let word_b = cb.alloc_n_cells(word_cap);
        let word_b_mask = cb.alloc_n_cells(word_cap);
        let word_b_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let word_b_addr_ext_1 = cb.alloc_n_cells(word_cap);

        let ref_val = cb.alloc_n_cells(LEN_OF_REFERENCE_VALUE);
        let ref_val_mask = cb.alloc_n_cells(LEN_OF_REFERENCE_VALUE);

        Self {
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            word_a_addr_ext_1,
            word_b,
            word_b_mask,
            word_b_addr_ext_0,
            word_b_addr_ext_1,
            ref_val,
            ref_val_mask,
        }
    }
}
