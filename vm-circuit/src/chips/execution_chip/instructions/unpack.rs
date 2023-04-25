// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word, WordA, WordB};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{
    rw_table::RWLookup, rw_table::RWTarget, LookupsWithCondition,
};
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
use logger::prelude::*;

#[derive(Clone, Debug)]
pub struct Unpack<F: FieldExt> {
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,
    word_b: Vec<Cell<F>>,
    word_b_mask: Vec<Cell<F>>,
    word_b_addr_ext_0: Vec<Cell<F>>,
    word_b_addr_ext_1: Vec<Cell<F>>,
    word_address: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for Unpack<F> {
    const NAME: &'static str = "UNPACK";

    const OPCODE: Opcode = Opcode::Unpack;

    fn configure(
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) -> Self {
        //Unpack
        let cond = cells.conditions[Opcode::Unpack.index()].expression.clone();

        // alloc cell
        let word_a = cb.query_n_cells(WORD_CAPACITY);
        let word_a_mask = cb.query_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_0 = cb.query_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_1 = cb.query_n_cells(WORD_CAPACITY);
        let word_b = cb.query_n_cells(WORD_CAPACITY);
        let word_b_mask = cb.query_n_cells(WORD_CAPACITY);
        let word_b_addr_ext_0 = cb.query_n_cells(WORD_CAPACITY);
        let word_b_addr_ext_1 = cb.query_n_cells(WORD_CAPACITY);
        let word_address = cb.query_n_cells(WORD_CAPACITY);

        let field_num = cells.auxiliary_1.expression.clone();
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            + field_num
            - 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + word_element_num.clone() * 2.expr();
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

        // word_a used for struct and word_b used for unpacked fields.
        for (i, item) in word_b.iter().enumerate().take(WORD_CAPACITY) {
            lookups.rw_lookups.push((
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    word_a_addr_ext_0[i].expression.clone(),
                    word_a_addr_ext_1[i].expression.clone(),
                    item.expression.clone(),
                ),
                cond.clone() * (1.expr() - word_a_mask[i].expression.clone()),
            ));

            lookups.rw_lookups.push((
                RWLookup {
                    gc: cells.gc.expression.clone() + word_element_num.clone() + (i as u64).expr(),
                    rw_target: (RWTarget::Stack as u64).expr(),
                    rw: (RW::WRITE as u64).expr(),
                    frame_index: 0.expr(),
                    address: word_address[i].expression.clone(),
                    address_ext_0: word_b_addr_ext_0[i].expression.clone(),
                    address_ext_1: word_b_addr_ext_1[i].expression.clone(),
                    value: item.expression.clone(),
                    sd_index: 0.expr(),
                },
                cond.clone() * (1.expr() - word_b_mask[i].expression.clone()),
            ));
        }

        //  word_a.address_ext_0 equal to word_b.address
        //  word_a.address_ext_1 equal to word_b.address_ext_0
        for i in 0..WORD_CAPACITY {
            let constraint = cond.clone()
                * word_a_mask[i].expression.clone()
                * (word_address[i].expression.clone() - word_a_addr_ext_0[i].expression.clone());
            cb.add_constraint("unpack_address_eq", constraint);
            let constraint = cond.clone()
                * word_a_mask[i].expression.clone()
                * (word_b_addr_ext_0[i].expression.clone()
                    - word_a_addr_ext_1[i].expression.clone());
            cb.add_constraint("unpack_address_ext_0_eq", constraint);
        }

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Unpack,
            cells.auxiliary_2.expression.clone(),
            &mut lookups.bytecode_lookups,
            cond,
        );
        Self {
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            word_a_addr_ext_1,
            word_b,
            word_b_mask,
            word_b_addr_ext_0,
            word_b_addr_ext_1,
            word_address,
        }
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let field_num = step.auxiliary_1.as_ref().ok_or_else(|| {
            error!("auxiliary_1 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_1
            .assign(region, offset, field_num.value())?;

        // assign
        let word_a = WordA {
            word_a: self.word_a.clone(),
            word_a_mask: self.word_a_mask.clone(),
            word_a_addr_ext_0: self.word_a_addr_ext_0.clone(),
            word_a_addr_ext_1: self.word_a_addr_ext_1.clone(),
        };
        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;
        Word::assign_word_a(
            region,
            offset,
            step,
            rw_operations,
            &word_a,
            step.gc,
            word_element_num,
        )?;

        let word_b = WordB {
            word_b: self.word_b.clone(),
            word_b_mask: self.word_b_mask.clone(),
            word_b_addr_ext_0: self.word_b_addr_ext_0.clone(),
            word_b_addr_ext_1: self.word_b_addr_ext_1.clone(),
        };
        Word::assign_word_b_with_address(
            region,
            offset,
            rw_operations,
            &word_b,
            &self.word_address,
            step.gc + word_element_num,
            word_element_num,
        )?;

        let sd_idx = step.auxiliary_2.as_ref().ok_or_else(|| {
            error!("auxiliary_2 is None");
            Error::Synthesis
        })?;
        cells.auxiliary_2.assign(region, offset, sd_idx.value())?;

        Ok(())
    }
}
