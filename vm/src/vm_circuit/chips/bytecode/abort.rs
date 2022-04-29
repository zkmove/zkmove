// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::bytecode::common::LookupBytecode;
use crate::vm_circuit::chips::bytecode::{BytecodeInterface, Opcode};
use crate::vm_circuit::chips::lookup_tables::{BytecodeLookup, RWLookup};
use crate::vm_circuit::chips::step_chip::StepChipCells;
use crate::vm_circuit::chips::utilities::Expr;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct Abort<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BytecodeInterface<F> for Abort<F> {
    fn configure(
        cells: &StepChipCells<F>,
        _constraints: &mut Vec<(&str, Expression<F>)>,
        _rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::Abort.index()].expression.clone();
        LookupBytecode::lookup_bytecode(cells, Opcode::Abort, 0.expr(), bytecode_lookups, cond);
    }

    fn assign(
        _region: &mut Region<'_, F>,
        _offset: usize,
        _step: &ExecutionStep<F>,
        _rw_table: &RWLookUpTable<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
