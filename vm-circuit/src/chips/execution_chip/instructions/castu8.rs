// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, UnaryOp};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::BYTES_NUM;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::{Cell, Expr, FieldBytes};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::prelude::*;
use movelang::value::NUM_OF_BYTES_U8;
use std::convert::TryInto;
use std::marker::PhantomData;

pub struct CastU8<F: FieldExt> {
    _value_a: Cell<F>,
    _value_c: Cell<F>,
    _bytes: [Cell<F>; BYTES_NUM],
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for CastU8<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.conditions[Opcode::CastU8.index()].expression.clone();
        let x = cells.value_a.expression.clone();
        let out = cells.value_c.expression.clone();

        // x = out
        let constraint = cond.clone() * (x - out.clone());
        constraints.push(("cast u8", constraint));

        // range check for out
        let bytes_1 = FieldBytes::from(cells.bytes.clone()).expr_with_n(NUM_OF_BYTES_U8);
        let constraint = cond.clone() * (out - bytes_1);
        constraints.push(("cast u8 range check", constraint));

        UnaryOp::constrain_unary_op(cells, constraints, cond.clone());
        UnaryOp::lookup_unary_op(cells, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::CastU8,
            0.expr(),
            &mut lookups.bytecode_lookups,
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
        UnaryOp::assign_unary_op(region, offset, step, rw_operations, cells)?;

        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        let cast_result = op.value().value().ok_or_else(|| {
            error!("cast_result is None");
            Error::Synthesis
        })?;

        let result_bytes: [u8; 32] = cast_result
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in cells.bytes.iter().enumerate() {
            byte.assign(region, offset, Some(F::from(result_bytes[index] as u64)))?;
        }

        Ok(())
    }
}
