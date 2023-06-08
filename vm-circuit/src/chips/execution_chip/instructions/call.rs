// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::generic_gadget::GenericTypeGadget;
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{
    call_lookup_table::CallLookup, rw_table::RWLookup, rw_table::RWTarget, LookupsWithCondition,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::WORD_CAPACITY;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::{ExecutionData, ExecutionStep};
use crate::witness::function_calls::EntryType;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;

#[derive(Clone, Debug)]
pub struct Call<const GENERIC: bool, F: FieldExt> {
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,
    word_address: Vec<Cell<F>>,
    type_cells: Option<GenericTypeGadget<F>>,
}

impl<const GENERIC: bool, F: FieldExt> InstructionGadget<F> for Call<GENERIC, F> {
    const NAME: &'static str = if GENERIC { "CALL_GENERIC" } else { "CALL" };

    const OPCODE: Opcode = if GENERIC {
        Opcode::CallGeneric
    } else {
        Opcode::Call
    };

    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.opcode_selector([Self::OPCODE]);

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
        for (i, item) in self.word_a.iter().enumerate().take(*WORD_CAPACITY) {
            lookups.rw_lookups.push((
                "call(stack pop)",
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    self.word_address[i].expression.clone() + offset.clone() + 1.expr(),
                    self.word_a_addr_ext_0[i].expression.clone(),
                    self.word_a_addr_ext_1[i].expression.clone(),
                    item.expression.clone(),
                ),
                cond.clone() * (1.expr() - self.word_a_mask[i].expression.clone()),
            ));
            lookups.rw_lookups.push((
                "call(locals write)",
                RWLookup {
                    gc: cells.gc.expression.clone() + word_element_num.clone() + (i as u64).expr(),
                    rw_target: (RWTarget::Locals as u64).expr(),
                    rw: (RW::WRITE as u64).expr(),
                    frame_index: cells.frame_index.expression.clone() + 1.expr(), // frame_index increase for callee
                    address: self.word_address[i].expression.clone(),
                    address_ext_0: self.word_a_addr_ext_0[i].expression.clone(),
                    address_ext_1: self.word_a_addr_ext_1[i].expression.clone(),
                    value: item.expression.clone(),
                    sd_index: 0.expr(),
                },
                cond.clone() * (1.expr() - self.word_a_mask[i].expression.clone()),
            ));
        }

        // (type_, module_index, function_index, pc, next_module_index, next_function_index, next_pc)
        // must be in the calls table.
        lookups.call_lookups.push((
            "opcode call",
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
        let function_instantiation_index = cb.curr.cells.auxiliary_2.expr();
        LookupBytecode::lookup_bytecode(
            cells,
            Self::OPCODE,
            function_instantiation_index,
            &mut lookups.bytecode_lookups,
            cond.clone(),
        );
        if GENERIC {
            // configure generic gadget
            self.type_cells
                .as_ref()
                .unwrap()
                .configure(cells, cb, lookups, cond);
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

        let word = Word {
            word: self.word_a.clone(),
            word_mask: self.word_a_mask.clone(),
            word_addr_ext_0: self.word_a_addr_ext_0.clone(),
            word_addr_ext_1: self.word_a_addr_ext_1.clone(),
        };
        Word::assign_word_with_address_and_filter(
            region,
            offset,
            rw_operations,
            &word,
            &self.word_address,
            step.gc,
            word_element_num,
            RW::WRITE,
        )?;
        if GENERIC {
            cells.auxiliary_4.assign(
                region,
                offset,
                step.auxiliary_4
                    .as_ref()
                    .ok_or_else(|| {
                        error!("auxiliary_4 is None");
                        Error::Synthesis
                    })?
                    .value(),
            )?;
            if let Some(ExecutionData::CallGeneric(data)) = &step.data {
                self.type_cells
                    .as_ref()
                    .unwrap()
                    .assign(region, offset, data.clone())?;
            } else {
                error!("expect execution data in {} gadget", Self::NAME);
                return Err(Error::Synthesis);
            }
        }
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let word_a = cb.alloc_n_cells(*WORD_CAPACITY);
        let word_a_mask = cb.alloc_n_cells(*WORD_CAPACITY);
        let word_a_addr_ext_0 = cb.alloc_n_cells(*WORD_CAPACITY);
        let word_a_addr_ext_1 = cb.alloc_n_cells(*WORD_CAPACITY);
        let word_address = cb.alloc_n_cells(*WORD_CAPACITY);

        let type_cells = if GENERIC {
            let callee_id = cb.next.cells.context_id.expr();
            let callee_module = cb.next.cells.module_index.expr();
            let callee_function = cb.next.cells.function_index.expr();
            let function_instantiation_index = cb.curr.cells.auxiliary_2.expr();
            let caller_callin_pc = cb.curr.cells.auxiliary_4.expr();
            let type_cells = GenericTypeGadget::construct(
                Self::NAME,
                cb,
                caller_callin_pc,
                callee_id,
                callee_module,
                callee_function,
                function_instantiation_index,
            );
            Some(type_cells)
        } else {
            None
        };
        Self {
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            word_a_addr_ext_1,
            word_address,
            type_cells,
        }
    }
}
