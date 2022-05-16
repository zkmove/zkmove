// Copyright (c) zkMove Authors

use crate::chips::execution_chips::instructions::common::{LoadOp, LookupBytecode};
use crate::chips::execution_chips::instructions::Instructions;
use crate::chips::execution_chips::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chips::opcode::Opcode;
use crate::chips::execution_chips::step_chip::StepChipCells;
use crate::circuit_inputs::execution_steps::ExecutionStep;
use crate::circuit_inputs::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct LdU8<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for LdU8<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        //LdU8
        let cond = cells.conditions[Opcode::LdU8.index()].expression.clone();
        LoadOp::constrain_ld_op(cells, constraints, cond.clone());
        LoadOp::lookup_ld_op(cells, rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::LdU8,
            cells.value_a.expression.clone(),
            bytecode_lookups,
            cond,
        );
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        cells.value_a.assign(region, offset, op.value().value())?;
        Ok(())
    }
}
