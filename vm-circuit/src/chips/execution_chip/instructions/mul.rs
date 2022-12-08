// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::{Expr, FieldBytes};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use movelang::value::{Value, NUM_OF_BYTES_U128, NUM_OF_BYTES_U64, NUM_OF_BYTES_U8};
use std::marker::PhantomData;

pub struct Mul<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for Mul<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::Mul.index()].expression.clone();

        let lhs = cells.value_a.expression.clone();
        let rhs = cells.value_b.expression.clone();
        let out = cells.value_c.expression.clone();
        let bytes_1 = FieldBytes::from(cells.bytes.clone()).expr_with_n(NUM_OF_BYTES_U8);
        let bytes_8 = FieldBytes::from(cells.bytes.clone()).expr_with_n(NUM_OF_BYTES_U64);
        let bytes_16 = FieldBytes::from(cells.bytes.clone()).expr_with_n(NUM_OF_BYTES_U128);
        let constraint = cond.clone() * (lhs * rhs - out.clone());
        constraints.push(("mul", constraint));

        // arithmetic overflow check
        // if bytes_len = NUM_OF_BYTES_U8, then bytes_1 == out
        // else if bytes_len = NUM_OF_BYTES_U64, then bytes_8 == out
        // else if bytes_len = NUM_OF_BYTES_U128, then bytes_16 == out
        let num_of_bytes = cells.auxiliary.expression.clone();
        let constraint = cond.clone()
            * (num_of_bytes.clone() - (NUM_OF_BYTES_U8 as u64).expr() + bytes_1 - out.clone())
            * (num_of_bytes.clone() - (NUM_OF_BYTES_U64 as u64).expr() + bytes_8 - out.clone())
            * (num_of_bytes - (NUM_OF_BYTES_U128 as u64).expr() + bytes_16 - out);
        constraints.push(("mul range check", constraint));

        BinaryOp::constrain_binary_op(cells, constraints, cond.clone());
        BinaryOp::lookup_binary_op(cells, rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(cells, Opcode::Mul, 0.expr(), bytecode_lookups, cond);
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        BinaryOp::assign_binary_op(region, offset, step, rw_operations, cells)?;

        // assign value into bytes
        let op = rw_operations.0.get(step.gc + 2).ok_or(Error::Synthesis)?;
        let v_u128 = op.value().value().unwrap().get_lower_128();
        let val = match op.value() {
            Value::U8(_) => Ok(v_u128 as u8 as u128),
            Value::U64(_) => Ok(v_u128 as u64 as u128),
            Value::U128(_) => Ok(v_u128),
            _ => Err(Error::Synthesis),
        };
        for (index, cell) in cells.bytes.iter().enumerate() {
            cell.assign(
                region,
                offset,
                Some(F::from(val.as_ref().unwrap().to_le_bytes()[index] as u64)),
            )?;
        }

        // assign auxiliary cell with number of bytes
        let num_of_bytes = match op.value() {
            Value::U8(_) => NUM_OF_BYTES_U8 as u128,
            Value::U64(_) => NUM_OF_BYTES_U64 as u128,
            Value::U128(_) => NUM_OF_BYTES_U128 as u128,
            _ => unimplemented!(),
        };
        cells
            .auxiliary
            .assign(region, offset, Some(F::from_u128(num_of_bytes)))?;

        Ok(())
    }
}
