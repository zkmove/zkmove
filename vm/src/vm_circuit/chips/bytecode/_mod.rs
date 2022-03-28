// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::bytecode::common::BinaryOp;
use crate::vm_circuit::chips::bytecode::{BytecodeInterface, Opcode};
use crate::vm_circuit::chips::lookup_tables::RWLookup;
use crate::vm_circuit::chips::step_chip::StepChipCells;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct Mod<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BytecodeInterface<F> for Mod<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
    ) {
        let cond = cells.conditions[Opcode::Mod.index()].expression.clone();

        let lhs = cells.value_a.expression.clone();
        let rhs = cells.value_b.expression.clone();
        let remainder = cells.value_c.expression.clone();
        let quotient = cells.auxiliary.expression.clone();
        let constraint = cond.clone() * (lhs - rhs * quotient - remainder);
        constraints.push(("Mod", constraint));
        BinaryOp::constrain_binary_op(cells, constraints, cond.clone());
        BinaryOp::lookup_binary_op(cells, rw_lookups, cond);
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_table: &RWLookUpTable<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        BinaryOp::assign_binary_op_with_auxiliary(region, offset, step, rw_table, cells)
    }
}
