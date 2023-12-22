// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::constant_lookup_table::ConstantLookup;

use crate::chips::execution_chip::instructions::common::value_gadget::ValueGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::plonk::Error;
use types::Field;

#[derive(Clone, Debug)]
pub struct LdConst<F: Field> {
    const_value: ValueGadget<F>,
}

impl<F: Field> InstructionGadget<F> for LdConst<F> {
    const NAME: &'static str = "LdConst";

    const OPCODE: Opcode = Opcode::LdConst;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let const_index = cells.auxiliary_1.expr();
        let flattened_value_len = cells.auxiliary_2.expr();

        let pc_expr =
            cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1u64.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            + 1u64.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + flattened_value_len.clone();
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

        self.const_value.configure(cb, flattened_value_len);

        for (i, _) in self.const_value.cells.word.iter().enumerate() {
            let write = RWLookup::stack_push(
                cells.gc.expression.clone() + (i as u64).expr(),
                cells.stack_size.expression.clone(),
                self.const_value.cells.word_addr_ext[i].expression.clone(),
                self.const_value.cells.word[i].expression.clone(),
            );
            cb.condition(
                1u64.expr() - self.const_value.cells.word_mask[i].expression.clone(),
                |cb| {
                    cb.add_lookup("ld_const(write)", write);
                    cb.add_lookup(
                        "constant lookup",
                        ConstantLookup {
                            module_index: cells.module_index.expr(),
                            constant_index: const_index.clone(),
                            addr_ext: self.const_value.cells.word_addr_ext[i].expression.clone(),
                            value: self.const_value.cells.word[i].expression.clone(),
                        },
                    );
                },
            );
        }

        LookupBytecode::lookup_bytecode(cb, cells, Self::OPCODE, const_index);
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let _const_index =
            Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;
        let flattened_value_len =
            Word::assign_step_value(region, offset, &step.auxiliary_2, &cells.auxiliary_2)?
                .get_lower_128() as usize;
        self.const_value
            .assign(region, offset, rw_operations, step.gc, flattened_value_len)?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let const_value = ValueGadget::construct(cb);

        Self { const_value }
    }
}
