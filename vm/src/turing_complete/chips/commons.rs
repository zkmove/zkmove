// Copyright (c) zkMove Authors

use halo2::arithmetic::FieldExt;
use halo2::circuit::{self, Region};
use halo2::plonk::{Advice, Column, Error, Expression, VirtualCells};
use halo2::poly::Rotation;
use move_binary_format::file_format::Bytecode;

pub const STEP_CHIP_WIDTH: usize = 10;
pub const STEP_HEIGHT: usize = 4;
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

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Option<F>,
    ) -> Result<circuit::Cell, Error> {
        region.assign_advice(
            || "assign cell",
            self.column,
            offset + self.rotation,
            || value.ok_or(Error::SynthesisError),
        )
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

// supported opcode
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Opcode {
    LdU8 = 0,
    LdU64,
    LdU128,
    Pop,
    Ret,
    Add,
    Mul,
}
// todo: we need a more secure way to get the number of Opcode members
pub const NUMBER_OF_BYTECODE_MEMBERS: usize = Opcode::Mul as usize + 1;

impl Opcode {
    pub fn index(&self) -> usize {
        *self as usize
    }
}

impl From<Bytecode> for Opcode {
    fn from(bytecode: Bytecode) -> Opcode {
        match bytecode {
            Bytecode::LdU8(_) => Opcode::LdU8,
            Bytecode::LdU64(_) => Opcode::LdU64,
            Bytecode::LdU128(_) => Opcode::LdU128,
            Bytecode::Pop => Opcode::Pop,
            Bytecode::Ret => Opcode::Ret,
            Bytecode::Add => Opcode::Add,
            Bytecode::Mul => Opcode::Mul,
            _ => unimplemented!(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StepChipCells<F: FieldExt> {
    pub pc: Cell<F>,
    pub stack_size: Cell<F>,
    pub call_index: Cell<F>,
    pub gc: Cell<F>,
    pub conditions: Vec<Cell<F>>,

    pub value_a: Cell<F>,
    pub value_b: Cell<F>,
    pub value_c: Cell<F>,

    pub next_pc: Cell<F>,
    pub next_stack_size: Cell<F>,
    pub next_call_index: Cell<F>,
    pub next_gc: Cell<F>,
}
