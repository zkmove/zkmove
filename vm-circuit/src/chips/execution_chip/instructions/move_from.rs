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
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub struct MoveFrom<F: FieldExt> {
    value_a: Cell<F>,
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for MoveFrom<F> {
    const NAME: &'static str = "MOVEFROM";

    const OPCODE: Opcode = Opcode::MoveFrom;

    fn configure(
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) -> Self {
        let cond = cells.conditions[Opcode::MoveFrom.index()]
            .expression
            .clone();

        // alloc cell
        let value_a = cb.query_cell();
        let word_a = cb.query_n_cells(WORD_CAPACITY);
        let word_a_mask = cb.query_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_0 = cb.query_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_1 = cb.query_n_cells(WORD_CAPACITY);

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_elem_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + word_elem_num.clone() * 3.expr() // two for global read resource, one for stack push value
            + 1.expr(); // stack pop account_address
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
        let account_address_expr = value_a.expression.clone();
        let sd_index_expr = cells.auxiliary_1.expression.clone();
        lookups.rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                account_address_expr.clone(),
            ),
            cond.clone(),
        ));

        for i in 0..WORD_CAPACITY {
            let (read_global, write_invalid_to_global, write_stack) =
                RWLookup::move_from_global_to_stack(
                    cells.gc.expression.clone() + (i as u64 + 1).expr(),
                    account_address_expr.clone(),
                    sd_index_expr.clone(),
                    cells.stack_size.expression.clone(),
                    word_a_addr_ext_0[i].expression.clone(),
                    word_a_addr_ext_1[i].expression.clone(),
                    word_a[i].expression.clone(),
                    word_elem_num.clone(),
                );
            lookups.rw_lookups.push((
                read_global,
                cond.clone() * (1.expr() - word_a_mask[i].expression.clone()),
            ));
            lookups.rw_lookups.push((
                write_invalid_to_global,
                cond.clone() * (1.expr() - word_a_mask[i].expression.clone()),
            ));
            lookups.rw_lookups.push((
                write_stack,
                cond.clone() * (1.expr() - word_a_mask[i].expression.clone()),
            ));
        }

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::MoveFrom,
            sd_index_expr,
            &mut lookups.bytecode_lookups,
            cond,
        );
        Self {
            value_a,
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
        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);

        // account address
        self.value_a.assign(region, offset, op.value().value())?;

        // resource structs
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
            step.gc + 1,
            word_element_num,
        )?;
        let sd_index = rw_operations
            .0
            .get(step.gc + 1)
            .ok_or(Error::Synthesis)?
            .sd_index();
        cells
            .auxiliary_1
            .assign(region, offset, Some(F::from_u128(sd_index as u128)))?;

        Ok(())
    }

    fn probe(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = cb.query_cell();
        let word_a = cb.query_n_cells(WORD_CAPACITY);
        let word_a_mask = cb.query_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_0 = cb.query_n_cells(WORD_CAPACITY);
        let word_a_addr_ext_1 = cb.query_n_cells(WORD_CAPACITY);

        Self {
            value_a,
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            word_a_addr_ext_1,
        }
    }
}
