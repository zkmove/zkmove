// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::LookupBytecode;
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::plonk::Error;
use movelang::value_ext::LEN_OF_SIMPLE_VALUE;
use types::Field;

use super::common::simple_value_gadget::SimpleValueGadget;
use super::common::Word;

#[derive(Clone, Debug)]
pub struct BrBool<F: Field, const TRUE: bool> {
    value: SimpleValueGadget<F>,
}

impl<F: Field, const TRUE: bool> InstructionGadget<F> for BrBool<F, TRUE> {
    const NAME: &'static str = match TRUE {
        true => "BRTRUE",
        false => "BRFALSE",
    };

    const OPCODE: Opcode = match TRUE {
        true => Opcode::BrTrue,
        false => Opcode::BrFalse,
    };

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // branch target is assigned in the auxiliary_1, condition is popped form stack as value
        let aux = cells.auxiliary_1.expression.clone();
        let pc = cells.pc.expression.clone();
        let next_pc = cb.next.cells.pc.expression.clone();
        let pc_expr = if TRUE {
            // auxiliary_1 * value + (pc + 1) * (1 - value) - next_pc = 0
            aux * self.value.cells.value().expression.clone()
                + (pc + 1u64.expr()) * (1u64.expr() - self.value.cells.value().expression.clone())
                - next_pc
        } else {
            // auxiliary_1 * (1 - value) + (pc + 1) * value - next_pc = 0
            aux * (1u64.expr() - self.value.cells.value().expression.clone())
                + (pc + 1u64.expr()) * self.value.cells.value().expression.clone()
                - next_pc
        };

        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 1u64.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + (LEN_OF_SIMPLE_VALUE as u64).expr();
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();

        cb.add_constraints(vec![
            ("BrBool pc", pc_expr),
            ("BrBool stack size", stack_size_expr),
            ("BrBool frame index", frame_index_expr),
            ("BrBool gc", gc_expr),
            ("BrBool module index", module_index),
            ("BrBool function index", func_index),
        ]);

        self.value.configure(cb);
        self.value.lookup_stack_pop(
            cb,
            cells.stack_size.expression.clone(),
            cells.gc.expression.clone(),
        );

        LookupBytecode::lookup_bytecode(
            cb,
            cells,
            Self::OPCODE,
            cells.auxiliary_1.expression.clone(),
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
        // assign next_pc into the auxiliary_1
        Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;

        // get value
        self.value.assign(region, offset, rw_operations, step.gc)?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value = SimpleValueGadget::construct(cb);

        Self { value }
    }
}
