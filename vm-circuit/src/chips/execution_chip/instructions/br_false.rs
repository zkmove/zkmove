// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::LookupBytecode;
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{AddrExtExpr, Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use movelang::word::ValueHeader;

#[derive(Clone, Debug)]
pub struct BrFalse<F: FieldExt> {
    value: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for BrFalse<F> {
    const NAME: &'static str = "BRFALSE";

    const OPCODE: Opcode = Opcode::BrFalse;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // branch target is assigned in the auxiliary_1, condition is popped form stack as value_a
        let aux = cells.auxiliary_1.expression.clone();
        let pc = cells.pc.expression.clone();
        let next_pc = cb.next.cells.pc.expression.clone();
        // auxiliary_1 * (1 - value) + (pc + 1) * value - next_pc = 0
        let pc_expr = aux * (1.expr() - self.value.expression.clone())
            + (pc + 1.expr()) * self.value.expression.clone()
            - next_pc;

        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone() + 2.expr();
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();

        cb.add_constraints(vec![
            ("BrFalse pc", pc_expr),
            ("BrFalse stack size", stack_size_expr),
            ("BrFalse frame index", frame_index_expr),
            ("BrFalse gc", gc_expr),
            ("BrFalse module index", module_index),
            ("BrFalse function index", func_index),
        ]);

        cb.add_lookup(
            "br_false(stack pop value header)",
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "br_false(stack pop value)",
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone(),
                1.addr_ext_offset_expr(),
                0.expr(),
                self.value.expression.clone(),
            ),
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
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        // assign next_pc into the auxiliary_1
        let aux_value = step.auxiliary_1.as_ref().ok_or_else(|| {
            error!("auxiliary_1 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_1
            .assign(region, offset, aux_value.value())?;

        // get value
        let op = rw_operations.0.get(step.gc + 1).ok_or_else(|| {
            error!("gc is is None");
            Error::Synthesis
        })?;
        debug_assert!(op.rw() == RW::READ);
        self.value.assign(region, offset, op.value().value())?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value = cb.alloc_cell();

        Self { value }
    }
}
