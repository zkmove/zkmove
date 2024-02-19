// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::value_gadget::ValueGadget;
use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use types::Field;

#[derive(Clone, Debug)]
pub struct CopyLoc<F: Field> {
    value: ValueGadget<F>,
}

impl<F: Field> InstructionGadget<F> for CopyLoc<F> {
    const NAME: &'static str = "COPYLOC";

    const OPCODE: Opcode = Opcode::CopyLoc;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr =
            cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1u64.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            + 1u64.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let flattened_value_len = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2u64.expr() * flattened_value_len.clone();
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

        self.value.configure(cb, flattened_value_len.clone());

        for (i, _) in self.value.cells.word.iter().enumerate() {
            let (read, write) = RWLookup::locals_copy(
                cells.gc.expression.clone() + (i as u64).expr(),
                cells.frame_index.expression.clone(),
                cells.locals_index.expression.clone(),
                cells.stack_size.expression.clone(),
                self.value.cells.word_addr_ext[i].expression.clone(),
                self.value.cells.word[i].expression.clone(),
                flattened_value_len.clone(), // flattened_value_len
            );
            cb.condition(
                1u64.expr() - self.value.cells.word_mask[i].expression.clone(),
                |cb| {
                    cb.add_lookup("copy_loc(read)", read);
                    cb.add_lookup("copy_loc(write)", write);
                },
            );
        }

        LookupBytecode::lookup_bytecode(
            cb,
            cells,
            Opcode::CopyLoc,
            cells.locals_index.expression.clone(),
        );
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_operations: &RWOperations,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let flattened_value_len =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;

        self.value
            .assign(region, offset, rw_operations, step.gc, flattened_value_len)?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let value = ValueGadget::construct(cb);

        Self { value }
    }
}
