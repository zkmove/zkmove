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
use std::marker::PhantomData;

pub struct Not<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for Not<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::Not.index()].expression.clone();

        let x = cells.value_a.expression.clone();
        let out = cells.value_c.expression.clone();
        // 1 - x = out
        let constraint = cond.clone() * (1.expr() - x - out);
        constraints.push(("Not", constraint));
        UnaryOp::constrain_unary_op(cells, constraints, cond.clone());
        UnaryOp::lookup_unary_op(cells, rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(cells, Opcode::Not, 0.expr(), bytecode_lookups, cond);
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        UnaryOp::assign_unary_op(region, offset, step, rw_operations, cells)
    }
}
