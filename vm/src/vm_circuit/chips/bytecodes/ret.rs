// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::bytecodes::common::RWLookup;
use crate::vm_circuit::chips::step_chip::StepChipCells;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct Ret<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Ret<F> {
    pub fn configure(
        _cells: &StepChipCells<F>,
        _constraints: &mut Vec<(&str, Expression<F>)>,
        _rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
    ) {
    }

    pub fn assign(
        _region: &mut Region<'_, F>,
        _offset: usize,
        _step: &ExecutionStep<F>,
        _rw_table: &RWLookUpTable<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
