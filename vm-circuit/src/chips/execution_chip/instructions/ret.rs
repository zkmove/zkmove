// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::LookupBytecode;
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::call_lookup_table::CallLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Expr, SubInvert};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::function_calls::EntryType;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct Ret<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> InstructionGadget<F> for Ret<F> {
    const NAME: &'static str = "RET";

    const OPCODE: Opcode = Opcode::Ret;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let frame_index = cells.frame_index.expression.clone();
        let inverse = cells.auxiliary_1.expression.clone();

        // constrain the inverse, if frame_index != 0, frame_index * inverse(frame_index) == 1
        let frame_index_expr =
            frame_index.clone() * (frame_index.clone() * inverse.clone() - 1.expr());

        // if frame_index == 0, the next step will be 'Nop' or 'Stop', we have
        // frame_index * inverse(frame_index) != 1
        // next_pc == pc
        let pc_expr = (frame_index.clone() * inverse.clone() - 1.expr())
            * (cb.next.cells.pc.expression.clone() - cells.pc.expression.clone());

        // gc should not change
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone();
        cb.add_constraints(vec![
            ("frame_index", frame_index_expr),
            ("pc", pc_expr),
            ("gc", gc_expr),
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

        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Ret, 0.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        _rw_table: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        cells
            .auxiliary_1
            .assign(region, offset, (step.frame_index as usize).sub_invert(0))?;

        Ok(())
    }

    fn construct(_cb: &mut ConstraintBuilder<F>) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}
