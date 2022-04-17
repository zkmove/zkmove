// Copyright (c) zkMove Authors

use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Region};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use logger::prelude::*;

#[derive(Clone, Debug)]
pub struct Cell<F: FieldExt> {
    pub expression: Expression<F>,
    pub column: Column<Advice>,
    pub rotation: Rotation,
}

impl<F: FieldExt> Cell<F> {
    pub fn new(meta: &mut VirtualCells<F>, column: Column<Advice>, rotation: i32) -> Self {
        Cell {
            expression: meta.query_advice(column, Rotation(rotation)),
            column,
            rotation: Rotation(rotation),
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
            (offset as i32 + self.rotation.0) as usize,
            || {
                value.ok_or_else(|| {
                    error!("assigned value is None");
                    Error::Synthesis
                })
            },
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

pub(crate) trait SubInvert<F: FieldExt> {
    fn sub_invert(&self, other: usize) -> Option<F>;
}

impl<F: FieldExt> SubInvert<F> for usize {
    fn sub_invert(&self, other: usize) -> Option<F> {
        if *self == other {
            Some(F::one())
        } else {
            let delta = F::from_u128(*self as u128) - F::from_u128(other as u128);
            delta.invert().into()
        }
    }
}
