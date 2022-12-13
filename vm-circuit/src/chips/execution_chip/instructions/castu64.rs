// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, UnaryOp};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use movelang::value::{Value, NUM_OF_BYTES_U128, NUM_OF_BYTES_U64, NUM_OF_BYTES_U8};
use std::marker::PhantomData;

pub struct CastU64<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for CastU64<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::CastU64.index()].expression.clone();
        let x = cells.value_a.expression.clone();
        let out = cells.value_c.expression.clone();

        // x = out
        let constraint = cond.clone() * (x - out);
        constraints.push(("cast u64", constraint));

        // bytes_len = NUM_OF_BYTES_U64
        let num_of_bytes = cells.auxiliary_1.expression.clone();
        let constraint = cond.clone() * (num_of_bytes - (NUM_OF_BYTES_U64 as u64).expr());
        constraints.push(("castu64 length check", constraint));

        UnaryOp::constrain_unary_op(cells, constraints, cond.clone());
        UnaryOp::lookup_unary_op(cells, rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(cells, Opcode::CastU64, 0.expr(), bytecode_lookups, cond);
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        UnaryOp::assign_unary_op(region, offset, step, rw_operations, cells)?;

        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        // assign auxiliary cell with number of bytes
        let num_of_bytes = match op.value() {
            Value::U8(_) => NUM_OF_BYTES_U8 as u128,
            Value::U64(_) => NUM_OF_BYTES_U64 as u128,
            Value::U128(_) => NUM_OF_BYTES_U128 as u128,
            _ => unimplemented!(),
        };
        cells
            .auxiliary_1
            .assign(region, offset, Some(F::from_u128(num_of_bytes)))?;

        Ok(())
    }
}
