// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct Exists<const GENERIC: bool, F: Field> {
    _marker: PhantomData<F>,
}

impl<const GENERIC: bool, F: Field> InstructionGadget<F> for Exists<GENERIC, F> {
    const NAME: &'static str = if GENERIC { "EXISTS_GENERIC" } else { "EXISTS" };

    const OPCODE: Opcode = if GENERIC {
        Opcode::ExistsGeneric
    } else {
        Opcode::Exists
    };
    fn configure(&self, _cells: &StepChipCells<F>, _cb: &mut ConstraintBuilder<F>) {}

    fn assign(
        &self,
        _region: &mut Region<'_, F>,
        _offset: usize,
        _step: &ExecutionStep,
        _rw_operations: &RWOperations,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn construct(_cb: &mut ConstraintBuilder<F>) -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}
