// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::LoadOp;
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Cell;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::value_ext::{LOWER_FIELD_OFFSET, UPPER_FIELD_OFFSET};

#[derive(Clone, Debug)]
pub struct LdU256<F: FieldExt> {
    value_hi: Cell<F>,
    value_lo: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for LdU256<F> {
    const NAME: &'static str = "LdU256";

    const OPCODE: Opcode = Opcode::LdU256;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        //LdU256

        LoadOp::constrain_ld_op(cells, cb);
        // TODO. need to process 2 fields
        // LoadOp::lookup_ld_op(cb, cells, &self.value_hi, &self.value_lo);
        LoadOp::lookup_ld_op(cb, cells, &self.value_lo);
        // LookupBytecode::lookup_bytecode(cb, cells, Opcode::LdU256, self.value_lo.expression.clone());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let value_hi = &self.value_hi;
        let op = rw_operations
            .0
            .get(step.gc + UPPER_FIELD_OFFSET)
            .ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        value_hi.assign(region, offset, op.value().value())?;

        let value_lo = &self.value_lo;
        let op = rw_operations
            .0
            .get(step.gc + LOWER_FIELD_OFFSET)
            .ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        value_lo.assign(region, offset, op.value().value())?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_hi = cb.alloc_cell();
        let value_lo = cb.alloc_cell();

        Self { value_hi, value_lo }
    }
}
