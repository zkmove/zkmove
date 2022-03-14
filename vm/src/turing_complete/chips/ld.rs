// Copyright (c) zkMove Authors

use crate::turing_complete::chips::commons::*;
use halo2::plonk::Expression;
use halo2::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem},
};
use std::marker::PhantomData;

pub struct LdConfig {
    pub advice: [Column<Advice>; STEP_CHIP_WIDTH],
}

pub struct LdChip<F: FieldExt> {
    config: LdConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> LdChip<F> {
    pub fn constrain_ld_op(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<Expression<F>>,
        cond: Expression<F>,
    ) {
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            + 1.expr();
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
    ) -> LdConfig {
        // for column in &advice {
        //     meta.enable_equality((*column).into());
        // }

        //LdU8
        let cond = cells.conditions[Bytecode::LdU8.index()].expression.clone();
        LdChip::constrain_ld_op(cells, constraints, cond);

        //LdU64
        let cond = cells.conditions[Bytecode::LdU64.index()].expression.clone();
        LdChip::constrain_ld_op(cells, constraints, cond);

        //LdU128
        let cond = cells.conditions[Bytecode::LdU128.index()]
            .expression
            .clone();
        LdChip::constrain_ld_op(cells, constraints, cond);

        LdConfig { advice }
    }
}
