// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use fields::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct Stop<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> InstructionGadget<F> for Stop<F> {
    const NAME: &'static str = "STOP";

    const OPCODE: Opcode = Opcode::Stop;

    fn configure(&self, _cells: &StepChipCells<F>, _cb: &mut ConstraintBuilder<F>) {}

    fn assign(
        &self,
        _region: &mut Region<'_, F>,
        _offset: usize,
        _step: &ExecutionStep<F>,
        _rw_table: &RWOperations<F>,
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
