// Copyright (c) zkMove Authors

use crate::turing_complete::chips::commons::*;
use halo2::plonk::Expression;
use halo2::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem},
};
use std::marker::PhantomData;

pub struct PopConfig {
    pub advice: [Column<Advice>; STEP_CHIP_WIDTH],
}

pub struct PopChip<F: FieldExt> {
    config: PopConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> PopChip<F> {
    pub fn constrain_pop_op(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<Expression<F>>,
        cond: Expression<F>,
    ) {
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - 1.expr();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 1.expr();
        constraints.append(&mut vec![
            cond.clone() * pc_expr,
            cond.clone() * stack_size_expr,
            cond.clone() * call_index_expr,
            cond * gc_expr,
        ]);
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; STEP_CHIP_WIDTH],
        cells: &StepChipCells<F>,
        constraints: &mut Vec<Expression<F>>,
    ) -> PopConfig {
        // for column in &advice {
        //     meta.enable_equality((*column).into());
        // }

        //LdU8
        let cond = cells.conditions[Bytecode::Pop.index()].expression.clone();
        PopChip::constrain_pop_op(cells, constraints, cond);

        PopConfig { advice }
    }
}
