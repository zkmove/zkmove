// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word, WordA};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::WORD_CAPACITY;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub struct StLoc<F: FieldExt> {
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for StLoc<F> {
    const NAME: &'static str = "STLOC";

    const OPCODE: Opcode = Opcode::StLoc;

    fn configure(
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) -> Self {
        let cond = cells.conditions[Opcode::StLoc.index()].expression.clone();

        // alloc cell
        let word_a = cb.query_n_cells(WORD_CAPACITY);
        let word_a_mask = cb.query_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_0 = cb.query_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_1 = cb.query_n_cells(WORD_CAPACITY);

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2.expr() * word_element_num.clone();
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

        for i in 0..WORD_CAPACITY {
            let (read, write) = RWLookup::locals_store(
                cells.gc.expression.clone() + (i as u64).expr(),
                cells.frame_index.expression.clone(),
                cells.locals_index.expression.clone(),
                cells.stack_size.expression.clone(),
                word_a_addr_ext_0[i].expression.clone(),
                word_a_addr_ext_1[i].expression.clone(),
                word_a[i].expression.clone(),
                word_element_num.clone(), // word_element_num
            );

            lookups.rw_lookups.push((
                read,
                cond.clone() * (1.expr() - word_a_mask[i].expression.clone()),
            ));
            lookups.rw_lookups.push((
                write,
                cond.clone() * (1.expr() - word_a_mask[i].expression.clone()),
            ));
        }

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::StLoc,
            cells.locals_index.expression.clone(),
            &mut lookups.bytecode_lookups,
            cond,
        );
        Self {
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            word_a_addr_ext_1,
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
        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;

        let word_a = WordA {
            word_a: self.word_a.clone(),
            word_a_mask: self.word_a_mask.clone(),
            word_a_addr_ext_0: self.word_a_addr_ext_0.clone(),
            word_a_addr_ext_1: self.word_a_addr_ext_1.clone(),
        };
        Word::assign_word_a(
            region,
            offset,
            step,
            rw_operations,
            &word_a,
            step.gc,
            word_element_num,
        )?;

        Ok(())
    }
}
