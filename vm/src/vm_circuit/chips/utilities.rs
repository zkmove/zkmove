// Copyright (c) zkMove Authors

use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Region};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;

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
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice(
            || "assign cell",
            self.column,
            offset + self.rotation,
            || value.ok_or(Error::Synthesis),
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
