// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word, WordB};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{
    call_lookup_table::CallLookup, rw_table::RWLookup, rw_table::RWTarget, LookupsWithCondition,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::WORD_CAPACITY;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::function_calls::EntryType;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;

#[derive(Clone, Debug)]
pub struct Call<F: FieldExt> {
    word_b: Vec<Cell<F>>,
    word_b_mask: Vec<Cell<F>>,
    word_b_addr_ext_0: Vec<Cell<F>>,
    word_b_addr_ext_1: Vec<Cell<F>>,
    word_address: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for Call<F> {
    const NAME: &'static str = "CALL";

    const OPCODE: Opcode = Opcode::Call;

    fn configure(
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) -> Self {
        let cond = cells.conditions[Opcode::Call.index()].expression.clone();

        // alloc cell
        let word_b = cb.query_n_cells(WORD_CAPACITY);
        let word_b_mask = cb.query_n_cells(WORD_CAPACITY);
        let word_b_addr_ext_0 = cb.query_n_cells(WORD_CAPACITY);
        let word_b_addr_ext_1 = cb.query_n_cells(WORD_CAPACITY);
        let word_address = cb.query_n_cells(WORD_CAPACITY);

        let arg_num = cells.auxiliary_1.expression.clone();
        // next pc is always 0
        let pc_expr = cb.next.cells.pc.expression.clone();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - arg_num.clone();
        // frame index increase 1
        let frame_index_expr = cells.frame_index.expression.clone()
            - cb.next.cells.frame_index.expression.clone()
            + 1.expr();
        // each argument has 2 rw operations
        let word_element_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + word_element_num.clone() * 2.expr();
        cb.add_constraints(vec![
            ("Call pc", cond.clone() * pc_expr),
            ("Call stack_size", cond.clone() * stack_size_expr),
            ("Call frame_index", cond.clone() * frame_index_expr),
            ("Call gc", cond.clone() * gc_expr),
        ]);

        // stack address of first argument, which is used to offset between stack and locals address
        let offset = cells.stack_size.expression.clone() - arg_num;
        for (i, item) in word_b.iter().enumerate().take(WORD_CAPACITY) {
            lookups.rw_lookups.push((
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    word_address[i].expression.clone() + offset.clone() + 1.expr(),
                    word_b_addr_ext_0[i].expression.clone(),
                    word_b_addr_ext_1[i].expression.clone(),
                    item.expression.clone(),
                ),
                cond.clone() * (1.expr() - word_b_mask[i].expression.clone()),
            ));
            lookups.rw_lookups.push((
                RWLookup {
                    gc: cells.gc.expression.clone() + word_element_num.clone() + (i as u64).expr(),
                    rw_target: (RWTarget::Locals as u64).expr(),
                    rw: (RW::WRITE as u64).expr(),
                    frame_index: cells.frame_index.expression.clone() + 1.expr(), // frame_index increase for callee
                    address: word_address[i].expression.clone(),
                    address_ext_0: word_b_addr_ext_0[i].expression.clone(),
                    address_ext_1: word_b_addr_ext_1[i].expression.clone(),
                    value: item.expression.clone(),
                    sd_index: 0.expr(),
                },
                cond.clone() * (1.expr() - word_b_mask[i].expression.clone()),
            ));
        }

        // (type_, module_index, function_index, pc, next_module_index, next_function_index, next_pc)
        // must be in the calls table.
        lookups.call_lookups.push((
            CallLookup {
                type_: (EntryType::CALL as u64).expr(),
                module_index: cells.module_index.expression.clone(),
                function_index: cells.function_index.expression.clone(),
                pc: cells.pc.expression.clone(),
                next_module_index: cb.next.cells.module_index.expression.clone(),
                next_function_index: cb.next.cells.function_index.expression.clone(),
                next_pc: cb.next.cells.pc.expression.clone(),
            },
            cond.clone(),
        ));

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Call,
            cells.auxiliary_2.expression.clone(),
            &mut lookups.bytecode_lookups,
            cond,
        );
        Self {
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
        // assign arg_num
        let aux_value = step.auxiliary_1.as_ref().ok_or_else(|| {
            error!("auxiliary_1 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_1
            .assign(region, offset, aux_value.value())?;

        let func_handle_idx = step.auxiliary_2.as_ref().ok_or_else(|| {
            error!("auxiliary_2 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_2
            .assign(region, offset, func_handle_idx.value())?;

        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;

        let word_b = WordB {
            word_b: self.word_b.clone(),
            word_b_mask: self.word_b_mask.clone(),
            word_b_addr_ext_0: self.word_b_addr_ext_0.clone(),
            word_b_addr_ext_1: self.word_b_addr_ext_1.clone(),
        };
        Word::assign_word_b_with_address_and_filter(
            region,
            offset,
            rw_operations,
            &word_b,
            &self.word_address,
            step.gc,
            word_element_num,
            RW::WRITE,
        )?;

        Ok(())
    }

    fn probe(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let word_b = cb.query_n_cells(WORD_CAPACITY);
        let word_b_mask = cb.query_n_cells(WORD_CAPACITY);
        let word_b_addr_ext_0 = cb.query_n_cells(WORD_CAPACITY);
        let word_b_addr_ext_1 = cb.query_n_cells(WORD_CAPACITY);
        let word_address = cb.query_n_cells(WORD_CAPACITY);

        Self {
            word_b,
            word_b_mask,
            word_b_addr_ext_0,
            word_b_addr_ext_1,
            word_address,
        }
    }
}
