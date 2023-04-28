// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct VecPushBack<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> InstructionGadget<F> for VecPushBack<F> {
    const NAME: &'static str = "VECPUSHBACK";

    const OPCODE: Opcode = Opcode::VecPushBack;

    fn configure(
        &self,
        _cells: &StepChipCells<F>,
        _cb: &mut ConstraintBuilder<F>,
        _lookups: &mut LookupsWithCondition<F>,
    ) {
    }

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
