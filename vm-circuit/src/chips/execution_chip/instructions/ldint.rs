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
use movelang::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64, NUM_OF_BYTES_U8,
};
use movelang::value_ext::LOWER_FIELD_OFFSET;

#[derive(Clone, Debug)]
pub struct LdInt<F: FieldExt, const N_BYTES: usize> {
    value_a: Cell<F>,
}

impl<F: FieldExt, const N_BYTES: usize> InstructionGadget<F> for LdInt<F, N_BYTES> {
    const NAME: &'static str = match N_BYTES {
        NUM_OF_BYTES_U8 => "LDU8",
        NUM_OF_BYTES_U16 => "LDU16",
        NUM_OF_BYTES_U32 => "LDU32",
        NUM_OF_BYTES_U64 => "LDU64",
        NUM_OF_BYTES_U128 => "LDU128",
        _ => unreachable!(),
    };

    const OPCODE: Opcode = match N_BYTES {
        NUM_OF_BYTES_U8 => Opcode::LdU8,
        NUM_OF_BYTES_U16 => Opcode::LdU16,
        NUM_OF_BYTES_U32 => Opcode::LdU32,
        NUM_OF_BYTES_U64 => Opcode::LdU64,
        NUM_OF_BYTES_U128 => Opcode::LdU128,
        _ => unreachable!(),
    };

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        LoadOp::constrain_ld_op(cells, cb);
        LoadOp::lookup_ld_op(cb, cells, &self.value_a);
        LookupBytecode::lookup_bytecode(cb, cells, Self::OPCODE, self.value_a.expression.clone());
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
