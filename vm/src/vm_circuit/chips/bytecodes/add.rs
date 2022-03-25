// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::bytecodes::common::BinaryOp;
use crate::vm_circuit::chips::bytecodes::common::Opcode;
use crate::vm_circuit::chips::bytecodes::common::RWLookup;
use crate::vm_circuit::chips::step_chip::StepChipCells;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct Add<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Add<F> {
    pub fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
    ) {
        //Add
        let cond = cells.conditions[Opcode::Add.index()].expression.clone();

        let lhs = cells.value_a.expression.clone();
        let rhs = cells.value_b.expression.clone();
        let out = cells.value_c.expression.clone();
        let constraint = cond.clone() * (lhs + rhs - out);
        constraints.push(("add", constraint));
        BinaryOp::constrain_binary_op(cells, constraints, cond.clone());
        BinaryOp::lookup_binary_op(cells, rw_lookups, cond);
    }

    pub fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_table: &RWLookUpTable<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        BinaryOp::assign_binary_op(region, offset, step, rw_table, cells)
    }
}
