// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct MoveTo<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for MoveTo<F> {
    fn configure(
        _cells: &StepChipCells<F>,
        _constraints: &mut Vec<(&str, Expression<F>)>,
        _rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        _bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
    }

    fn assign(
        _region: &mut Region<'_, F>,
        _offset: usize,
        _step: &ExecutionStep<F>,
        _rw_operations: &RWOperations<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
