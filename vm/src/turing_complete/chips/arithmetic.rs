// Copyright (c) zkMove Authors

use crate::turing_complete::chips::commons::*;
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
        constraints: &mut Vec<Expression<F>>,
    ) -> ArithmeticConfig {
        // for column in &advice {
        //     meta.enable_equality((*column).into());
        // }

        //Add
        let lhs = cells.value_a.expression.clone();
        let rhs = cells.value_b.expression.clone();
        let out = cells.value_c.expression.clone();
        let cond = cells.conditions[Bytecode::Add.index()].expression.clone();
        let constraint = cond * (lhs + rhs - out);
        constraints.push(constraint);

        //Mul
        let lhs = cells.value_a.expression.clone();
        let rhs = cells.value_b.expression.clone();
        let out = cells.value_c.expression.clone();
        let cond = cells.conditions[Bytecode::Mul.index()].expression.clone();
        let constraint = cond * (lhs * rhs - out);
        constraints.push(constraint);

        ArithmeticConfig { advice }
    }
}
