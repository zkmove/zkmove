// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::execution_chips::instructions::common::{BinaryOp, LookupBytecode};
use crate::vm_circuit::chips::execution_chips::instructions::Instructions;
use crate::vm_circuit::chips::execution_chips::lookup_tables::{BytecodeLookup, RWLookup};
use crate::vm_circuit::chips::execution_chips::opcode::Opcode;
use crate::vm_circuit::chips::execution_chips::step_chip::StepChipCells;
use crate::vm_circuit::chips::utilities::Expr;
use crate::vm_circuit::circuit_inputs::execution_steps::ExecutionStep;
use crate::vm_circuit::circuit_inputs::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct And<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for And<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::And.index()].expression.clone();

        let lhs = cells.value_a.expression.clone();
        let rhs = cells.value_b.expression.clone();
        let out = cells.value_c.expression.clone();
        let constraint = cond.clone() * (lhs * rhs - out);
        constraints.push(("And", constraint));
        BinaryOp::constrain_binary_op(cells, constraints, cond.clone());
        BinaryOp::lookup_binary_op(cells, rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(cells, Opcode::And, 0.expr(), bytecode_lookups, cond);
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        BinaryOp::assign_binary_op(region, offset, step, rw_operations, cells)
    }
}
