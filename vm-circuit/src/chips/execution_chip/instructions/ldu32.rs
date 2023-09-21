// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{
    get_field_from_op, LoadOp, LookupBytecode,
};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Cell;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::value_ext::LOWER_FIELD_OFFSET;

#[derive(Clone, Debug)]
pub struct LdU32<F: FieldExt> {
    value_a: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for LdU32<F> {
    const NAME: &'static str = "LDU32";

    const OPCODE: Opcode = Opcode::LdU32;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        //LdU32

        LoadOp::constrain_ld_op(cells, cb);
        LoadOp::lookup_ld_op(cb, cells, &self.value_a);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::LdU32, self.value_a.expression.clone());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let value_a = &self.value_a;
        let f = get_field_from_op(rw_operations, step.gc + LOWER_FIELD_OFFSET)?;
        value_a.assign(region, offset, Some(f))?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = cb.alloc_cell();

        Self { value_a }
    }
}
