// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{
    get_field_from_op, LoadOp, LookupBytecode,
};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::plonk::Error;
use movelang::value_ext::{LOWER_FIELD_OFFSET, UPPER_FIELD_OFFSET};
use types::Field;

use super::common::word_gadget::WordCells;

#[derive(Clone, Debug)]
pub struct LdU256<F: Field> {
    value: WordCells<F>,
}

impl<F: Field> InstructionGadget<F> for LdU256<F> {
    const NAME: &'static str = "LdU256";

    const OPCODE: Opcode = Opcode::LdU256;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        //LdU256

        LoadOp::constrain_ld_op(cells, cb);
        self.value.lookup_stack_push(
            cb,
            cells.stack_size.expression.clone(),
            cells.gc.expression.clone(),
        );
        LookupBytecode::lookup_bytecode_u256(
            cb,
            cells,
            Opcode::LdU256,
            self.value.hi.expression.clone(),
            self.value.lo.expression.clone(),
        );
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let value_hi = &self.value.hi;
        let f = get_field_from_op(rw_operations, step.gc + UPPER_FIELD_OFFSET)?;
        value_hi.assign(region, offset, Some(f))?;

        let value_lo = &self.value.lo;
        let f = get_field_from_op(rw_operations, step.gc + LOWER_FIELD_OFFSET)?;
        value_lo.assign(region, offset, Some(f))?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value = WordCells::<F>::construct(cb);

        Self { value }
    }
}
