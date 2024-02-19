// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LoadOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64, NUM_OF_BYTES_U8,
};
use types::Field;

use super::common::simple_value_gadget::SimpleValueGadget;

#[derive(Clone, Debug)]
pub struct LdInt<F: Field, const N_BYTES: usize> {
    value_a: SimpleValueGadget<F>,
}

impl<F: Field, const N_BYTES: usize> InstructionGadget<F> for LdInt<F, N_BYTES> {
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
        self.value_a.configure(cb);

        LoadOp::constrain_ld_op(cells, cb);
        self.value_a.lookup_stack_push(
            cb,
            cells.stack_size.expression.clone(),
            cells.gc.expression.clone(),
        );
        LookupBytecode::lookup_bytecode(
            cb,
            cells,
            Self::OPCODE,
            self.value_a.cells.value().expression.clone(),
        );
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_operations: &RWOperations,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        self.value_a
            .assign(region, offset, rw_operations, step.gc)?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = SimpleValueGadget::construct(cb);

        Self { value_a }
    }
}
