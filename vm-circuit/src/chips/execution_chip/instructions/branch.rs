// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::LookupBytecode;
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::plonk::Error;
use std::marker::PhantomData;
use types::Field;

use super::common::Word;

#[derive(Clone, Debug)]
pub struct Branch<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> InstructionGadget<F> for Branch<F> {
    const NAME: &'static str = "BRANCH";

    const OPCODE: Opcode = Opcode::Branch;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // next pc is assigned in the auxiliary_1
        let pc_expr = cells.auxiliary_1.expression.clone() - cb.next.cells.pc.expression.clone();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone();
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();
        cb.add_constraints(vec![
            ("branch pc", pc_expr),
            ("branch stack size", stack_size_expr),
            ("branch frame index", frame_index_expr),
            ("branch gc", gc_expr),
            ("branch module index", module_index),
            ("branch function index", func_index),
        ]);

        LookupBytecode::lookup_bytecode(
            cb,
            cells,
            Opcode::Branch,
            cells.auxiliary_1.expression.clone(),
        );
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        _rw_table: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        // assign next_pc into the auxiliary_1
        Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;
        Ok(())
    }

    fn construct(_cb: &mut ConstraintBuilder<F>) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}
