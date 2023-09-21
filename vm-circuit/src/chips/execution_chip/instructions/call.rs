// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::generic_gadget::GenericTypeGadget;
use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{
    call_lookup_table::CallLookup, rw_table::RWLookup, rw_table::RWTarget,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::NUM_OF_ARGS_CELLS;
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
    word_a_addr_ext: Vec<Cell<F>>,
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
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let is_native = cells.auxiliary_5.expression.clone();
        // config non-native function call
        cb.condition(1.expr() - is_native, |cb| {
            self.configure_non_native_call(cells, cb);
        });
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let is_native =
            Word::assign_step_value(region, offset, &step.auxiliary_5, &cells.auxiliary_5)?;
        match &is_native {
            v if v == &F::one() => return Ok(()),
            _ => {}
        }
        // assign arg_num
        let _aux_value =
            Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;
        let _func_handle_idx =
            Word::assign_step_value(region, offset, &step.auxiliary_2, &cells.auxiliary_2)?;
        let flattened_value_len =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;

        let word = Word {
            word: self.word_a.clone(),
            word_mask: self.word_a_mask.clone(),
            word_addr_ext: self.word_a_addr_ext.clone(),
        };
        Word::assign_word_with_address_and_filter(
            region,
            offset,
            rw_operations,
            &word,
            &self.word_address,
            step.gc,
            flattened_value_len,
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
        let word_a = cb.alloc_n_cells(NUM_OF_ARGS_CELLS);
        let word_a_mask = cb.alloc_n_cells(NUM_OF_ARGS_CELLS);
        let word_a_addr_ext = cb.alloc_n_cells(NUM_OF_ARGS_CELLS);
        let word_address = cb.alloc_n_cells(NUM_OF_ARGS_CELLS);

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
            word_a_addr_ext,
            word_address,
            type_cells,
        }
    }
}

impl<const GENERIC: bool, F: FieldExt> Call<GENERIC, F> {
    fn configure_non_native_call(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
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
        let flattened_value_len = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + flattened_value_len.clone() * 2.expr();
        cb.add_constraints(vec![
            ("Call pc", pc_expr),
            ("Call stack_size", stack_size_expr),
            ("Call frame_index", frame_index_expr),
            ("Call gc", gc_expr),
        ]);

        // stack address of first argument, which is used to offset between stack and locals address
        let offset = cells.stack_size.expression.clone() - arg_num;
        for (i, item) in self.word_a.iter().enumerate() {
            cb.condition(1.expr() - self.word_a_mask[i].expression.clone(), |cb| {
                cb.add_lookup(
                    "call(stack pop)",
                    RWLookup::stack_pop(
                        cells.gc.expression.clone() + (i as u64).expr(),
                        self.word_address[i].expression.clone() + offset.clone() + 1.expr(),
                        self.word_a_addr_ext[i].expression.clone(),
                        item.expression.clone(),
                    ),
                );
                cb.add_lookup(
                    "call(locals write)",
                    RWLookup {
                        gc: cells.gc.expression.clone()
                            + flattened_value_len.clone()
                            + (i as u64).expr(),
                        rw_target: (RWTarget::Locals as u64).expr(),
                        rw: (RW::WRITE as u64).expr(),
                        frame_index: cells.frame_index.expression.clone() + 1.expr(), // frame_index increase for callee
                        address: self.word_address[i].expression.clone(),
                        address_ext: self.word_a_addr_ext[i].expression.clone(),
                        value: item.expression.clone(),
                        sd_index: 0.expr(),
                    },
                );
            });
        }

        // (type_, module_index, function_index, pc, next_module_index, next_function_index, next_pc)
        // must be in the calls table.
        cb.add_lookup(
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
        );
        let function_instantiation_index = cb.curr.cells.auxiliary_2.expr();
        LookupBytecode::lookup_bytecode(cb, cells, Self::OPCODE, function_instantiation_index);
        if GENERIC {
            // configure generic gadget
            self.type_cells.as_ref().unwrap().configure(cells, cb);
        }
    }
}
