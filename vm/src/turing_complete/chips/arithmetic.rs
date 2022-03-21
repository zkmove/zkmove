// Copyright (c) zkMove Authors

use crate::turing_complete::chips::binary_op::BinaryOp;
use crate::turing_complete::chips::commons::*;
use crate::turing_complete::chips::lookup::RWLookup;
use halo2::plonk::Expression;
use halo2::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem},
};
use std::marker::PhantomData;

pub struct ArithmeticConfig {
    pub advice: [Column<Advice>; STEP_CHIP_WIDTH],
}

pub struct ArithmeticChip<F: FieldExt> {
    config: ArithmeticConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ArithmeticChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; STEP_CHIP_WIDTH],
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
    ) -> ArithmeticConfig {
        // for column in &advice {
        //     meta.enable_equality((*column).into());
        // }

        //Add
        let cond = cells.conditions[Opcode::Add.index()].expression.clone();

        let lhs = cells.value_a.expression.clone();
        let rhs = cells.value_b.expression.clone();
        let out = cells.value_c.expression.clone();
        let constraint = cond.clone() * (lhs + rhs - out);
        constraints.push(("add", constraint));
        BinaryOp::constrain_binary_op(cells, constraints, cond.clone());
        BinaryOp::lookup_binary_op(cells, rw_lookups, cond);

        //Mul
        let cond = cells.conditions[Opcode::Mul.index()].expression.clone();

        let lhs = cells.value_a.expression.clone();
        let rhs = cells.value_b.expression.clone();
        let out = cells.value_c.expression.clone();
        let constraint = cond.clone() * (lhs * rhs - out);
        constraints.push(("mul", constraint));
        BinaryOp::constrain_binary_op(cells, constraints, cond.clone());
        BinaryOp::lookup_binary_op(cells, rw_lookups, cond);

        ArithmeticConfig { advice }
    }
}
