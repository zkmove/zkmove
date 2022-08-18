// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LoadOp, LookupBytecode};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use proof_system::halo2_proofs::arithmetic::FieldExt;
use proof_system::halo2_proofs::circuit::Region;
use proof_system::halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct LdU64<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for LdU64<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        //LdU64
        let cond = cells.conditions[Opcode::LdU64.index()].expression.clone();
        LoadOp::constrain_ld_op(cells, constraints, cond.clone());
        LoadOp::lookup_ld_op(cells, rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::LdU64,
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
