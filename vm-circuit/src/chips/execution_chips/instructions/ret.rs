// Copyright (c) zkMove Authors

use crate::chips::execution_chips::instructions::common::LookupBytecode;
use crate::chips::execution_chips::instructions::Instructions;
use crate::chips::execution_chips::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chips::opcode::Opcode;
use crate::chips::execution_chips::step_chip::StepChipCells;
use crate::chips::utilities::Expr;
use crate::circuit_inputs::execution_steps::ExecutionStep;
use crate::circuit_inputs::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct Ret<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for Ret<F> {
    fn configure(
        cells: &StepChipCells<F>,
        _constraints: &mut Vec<(&str, Expression<F>)>,
        _rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::Ret.index()].expression.clone();
        LookupBytecode::lookup_bytecode(cells, Opcode::Ret, 0.expr(), bytecode_lookups, cond);
    }

    fn assign(
        _region: &mut Region<'_, F>,
        _offset: usize,
        _step: &ExecutionStep<F>,
        _rw_table: &RWOperations<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
