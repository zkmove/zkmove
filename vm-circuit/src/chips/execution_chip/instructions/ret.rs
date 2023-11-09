// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::value_gadget::ValueGadget;
use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::call_lookup_table::CallLookup;
use crate::chips::execution_chip::lookup_tables::pi_lookup_table::PILookup;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Expr, SubInvert};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::function_calls::EntryType;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use types::Field;

#[derive(Clone, Debug)]
pub struct Ret<F: Field> {
    value: ValueGadget<F>,
}

impl<F: Field> InstructionGadget<F> for Ret<F> {
    const NAME: &'static str = "RET";

    const OPCODE: Opcode = Opcode::Ret;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let stop_and_has_ret_val = cells.auxiliary_1.expression.clone();
        let flattened_value_len = cells.auxiliary_3.expression.clone();

        let constraint =
            stop_and_has_ret_val.clone() * (1u64.expr() - stop_and_has_ret_val.clone());
        cb.add_constraint("stop_and_has_ret_val is bool", constraint);

        let frame_index = cells.frame_index.expression.clone();
        let inverse = cells.auxiliary_2.expression.clone();

        // constrain the inverse, if frame_index != 0, frame_index * inverse(frame_index) == 1
        let frame_index_expr =
            frame_index.clone() * (frame_index.clone() * inverse.clone() - 1u64.expr());

        // if frame_index == 0, the next step will be 'Nop' or 'Stop', we have
        // frame_index * inverse(frame_index) != 1
        // next_pc == pc
        let pc_expr = (frame_index.clone() * inverse.clone() - 1u64.expr())
            * (cb.next.cells.pc.expression.clone() - cells.pc.expression.clone());

        let gc_expr_1 = (1u64.expr() - stop_and_has_ret_val.clone())
            * (cells.gc.expression.clone() - cb.next.cells.gc.expression.clone());
        // gc will change if there is a return value
        let gc_expr_2 = stop_and_has_ret_val.clone()
            * (cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
                + flattened_value_len.clone());

        cb.add_constraints(vec![
            ("pc", pc_expr),
            ("frame index", frame_index_expr),
            ("gc_1", gc_expr_1),
            ("gc_2", gc_expr_2),
        ]);

        // if frame_index != 0, the next step will be a normal bytecode,
        // (type_, module_index, function_index, pc, next_module_index, next_function_index, next_pc)
        // must be in calls table.
        // only take effect when frame_index != 0,
        cb.condition(frame_index * inverse, |cb| {
            cb.add_lookup(
                "opcode ret",
                CallLookup {
                    type_: (EntryType::RET as u64).expr(),
                    module_index: cells.module_index.expression.clone(),
                    function_index: cells.function_index.expression.clone(),
                    pc: cells.pc.expression.clone(),
                    next_module_index: cb.next.cells.module_index.expression.clone(),
                    next_function_index: cb.next.cells.function_index.expression.clone(),
                    next_pc: cb.next.cells.pc.expression.clone(),
                },
            );
        });

        //stop, has return value
        cb.condition(stop_and_has_ret_val.clone(), |cb| {
            self.value.configure(cb, flattened_value_len.clone());
        });
        for (i, _) in self.value.cells.word.iter().enumerate() {
            cb.condition(
                stop_and_has_ret_val.clone()
                    * (1u64.expr() - self.value.cells.word_mask[i].expression.clone()),
                |cb| {
                    cb.add_lookup(
                        "ret pop(stack)",
                        RWLookup::stack_pop(
                            cells.gc.expression.clone() + (i as u64).expr(),
                            cells.stack_size.expression.clone(),
                            self.value.cells.word_addr_ext[i].expression.clone(),
                            self.value.cells.word[i].expression.clone(),
                        ),
                    );
                },
            );
        }

        for (i, _) in self.value.cells.word.iter().enumerate() {
            cb.condition(
                stop_and_has_ret_val.clone()
                    * (1u64.expr() - self.value.cells.word_mask[i].expression.clone()),
                |cb| {
                    // see PILookupTable for details
                    cb.add_lookup(
                        "lookup pi",
                        PILookup {
                            idx: ((i * 2 + 1) as u64).expr(),
                            pi: self.value.cells.word_addr_ext[i].expression.clone(),
                        },
                    );
                    cb.add_lookup(
                        "lookup pi",
                        PILookup {
                            idx: ((i * 2 + 2) as u64).expr(),
                            pi: self.value.cells.word[i].expression.clone(),
                        },
                    );
                },
            );
        }

        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Ret, 0u64.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        cells
            .auxiliary_2
            .assign(region, offset, (step.frame_index).sub_invert(0))?;

        let stop_and_has_return_value =
            Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;

        if stop_and_has_return_value == F::ONE {
            let flattened_value_len =
                Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                    .get_lower_128() as usize;
            self.value
                .assign(region, offset, rw_operations, step.gc, flattened_value_len)?;
        }
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let value = ValueGadget::construct(cb);

        Self { value }
    }
}
