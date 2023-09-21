// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LoadOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::value_ext::LOWER_FIELD_OFFSET;

use super::common::get_field_from_op;

#[derive(Clone, Debug)]
pub struct LdFalse<F: FieldExt> {
    value_a: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for LdFalse<F> {
    const NAME: &'static str = "LDFALSE";

    const OPCODE: Opcode = Opcode::LdFalse;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        //LdFalse

        LoadOp::constrain_ld_op(cells, cb);
        LoadOp::lookup_ld_op(cb, cells, &self.value_a);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::LdFalse, 0.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let f = get_field_from_op(rw_operations, step.gc + LOWER_FIELD_OFFSET)?;
        self.value_a.assign(region, offset, Some(f))?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = cb.alloc_cell();

        Self { value_a }
    }
}
