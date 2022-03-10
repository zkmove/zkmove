// Copyright (c) zkMove Authors

use halo2::arithmetic::FieldExt;
use halo2::plonk::{Advice, Column, Expression, VirtualCells};
use halo2::poly::Rotation;

pub const STEP_CHIP_WIDTH: usize = 10;
pub const NUM_OF_STEP_STATE: usize = 4; //pc, stack_size, call_index, gc
pub const MAX_OPERANDS_PER_STEP: usize = 3; //value_a, value_b, value_c

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

// supported bytecode
#[derive(Copy, Clone)]
pub enum Bytecode {
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

pub struct StepChipCells<F: FieldExt> {
    pub pc: Cell<F>,
    pub stack_size: Cell<F>,
    pub call_index: Cell<F>,
    pub gc: Cell<F>,

    pub value_a: Cell<F>,
    pub value_b: Cell<F>,
    pub value_c: Cell<F>,

    pub conditions: Vec<Cell<F>>,
}
