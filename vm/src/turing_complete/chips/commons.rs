// Copyright (c) zkMove Authors

use halo2::arithmetic::FieldExt;
use halo2::plonk::{Advice, Column, Expression, VirtualCells};
use halo2::poly::Rotation;
use std::marker::PhantomData;

pub const STEP_CHIP_WIDTH: usize = 10;
pub const STEP_HEIGHT: usize = 40;
pub const NUM_OF_STEP_STATE: usize = 4; //pc, stack_size, call_index, gc
pub const MAX_OPERANDS_PER_STEP: usize = 3; //value_a, value_b, value_c

#[derive(Clone, Debug)]
pub struct Cell<F: FieldExt> {
    pub expression: Expression<F>,
    pub column: Column<Advice>,
    pub rotation: usize,
}

impl<F: FieldExt> Cell<F> {
    pub fn new(meta: &mut VirtualCells<F>, column: Column<Advice>, rotation: usize) -> Self {
        Cell {
            expression: meta.query_advice(column, Rotation(rotation as i32)),
            column,
            rotation,
        }
    }
}

pub(crate) trait Expr<F: FieldExt> {
    fn expr(&self) -> Expression<F>;
}

impl<F: FieldExt> Expr<F> for u64 {
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from(*self))
    }
}

// supported bytecode
#[derive(Copy, Clone)]
pub enum Bytecode {
    LdU8,
    LdU64,
    LdU128,
    Pop,
    Ret,
    Add,
    Mul,
    // ...
}

impl Bytecode {
    pub fn iterator() -> impl Iterator<Item = Self> {
        [Self::Add, Self::Mul].iter().copied()
    }
    pub fn amount() -> usize {
        Self::iterator().count()
    }

    pub fn index(&self) -> usize {
        *self as usize
    }
}

#[derive(Clone, Debug)]
pub struct StepChipCells<F: FieldExt> {
    pub pc: Cell<F>,
    pub stack_size: Cell<F>,
    pub call_index: Cell<F>,
    pub gc: Cell<F>,

    pub value_a: Cell<F>,
    pub value_b: Cell<F>,
    pub value_c: Cell<F>,

    pub conditions: Vec<Cell<F>>,

    pub next_pc: Cell<F>,
    pub next_stack_size: Cell<F>,
    pub next_call_index: Cell<F>,
    pub next_gc: Cell<F>,
}

pub struct StepStateTransition<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> StepStateTransition<F> {
    pub fn constrain_binary_op(
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
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 3.expr();
        constraints.append(&mut vec![
            cond.clone() * pc_expr,
            cond.clone() * stack_size_expr,
            cond.clone() * call_index_expr,
            cond * gc_expr,
        ]);
    }
}
