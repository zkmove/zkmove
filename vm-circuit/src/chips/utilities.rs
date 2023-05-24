// Copyright (c) zkMove Authors

use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Region};
use halo2_proofs::circuit::{Layouter, Value as CircuitValue};
use halo2_proofs::plonk::{Advice, Column, Error, Expression, TableColumn, VirtualCells};
use halo2_proofs::poly::Rotation;
use movelang::value::NUM_OF_BYTES_U128;
use std::convert::TryInto;

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
            || match value {
                Some(v) => CircuitValue::known(v),
                None => CircuitValue::unknown(),
            },
        )
    }

    pub fn assign_equality(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        cell: AssignedCell<F, F>,
        annotation: &str,
    ) -> Result<AssignedCell<F, F>, Error> {
        cell.copy_advice(
            || annotation,
            region,
            self.column,
            (offset as i32 + self.rotation.0) as usize,
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

// The internal representation of FieldExt is four 64-bits unsigned integer in little-endian order,
// This struct has 16 Cells, to hold the 16 bytes of the lower two u64.
pub struct FieldBytes<F: FieldExt>(pub(crate) [Cell<F>; 16]);

impl<F: FieldExt> From<Vec<Cell<F>>> for FieldBytes<F> {
    fn from(bytes: Vec<Cell<F>>) -> FieldBytes<F> {
        let bytes: [Cell<F>; 16] = bytes.try_into().unwrap_or_else(|v: Vec<Cell<F>>| {
            panic!(
                "Expected a Vec of length {} but it was {}",
                NUM_OF_BYTES_U128,
                v.len()
            )
        });
        FieldBytes(bytes)
    }
}

impl<F: FieldExt> Expr<F> for FieldBytes<F> {
    fn expr(&self) -> Expression<F> {
        let mut value = 0.expr();
        let mut multiplier = F::one();
        for byte in self.0.iter() {
            value = value + byte.expression.clone() * multiplier;
            multiplier *= F::from(256);
        }
        value
    }
}

impl<F: FieldExt> FieldBytes<F> {
    pub fn expr_with_n(&self, num: usize) -> Expression<F> {
        let mut value = 0.expr();
        let mut multiplier = F::one();
        for byte in self.0.iter().take(num) {
            value = value + byte.expression.clone() * multiplier;
            multiplier *= F::from(256);
        }
        value
    }

    pub fn expr_16bit(&self, num: usize) -> Expression<F> {
        let mut value = 0.expr();
        let mut multiplier = F::one();
        for byte in self.0.iter().take(num) {
            value = value + byte.expression.clone() * multiplier;
            multiplier *= F::from(1 << 16);
        }
        value
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

pub(crate) trait DeltaInvert<F: FieldExt> {
    fn delta_invert(&self, other: F) -> Option<F>;
}
impl<F: FieldExt> DeltaInvert<F> for F {
    fn delta_invert(&self, other: F) -> Option<F> {
        if *self == other {
            Some(F::one())
        } else {
            let delta = *self - other;
            delta.invert().into()
        }
    }
}

// a special table with solo column and the value same as index.
// which is to garantuee value is among [0, max].
pub(crate) fn assign_index_table<F: FieldExt>(
    layouter: &mut impl Layouter<F>,
    table_name: &str,
    column: TableColumn,
    max_row: usize,
) -> Result<(), Error> {
    layouter.assign_table(
        || format!("{:?}", table_name),
        |mut table_column| {
            (0..=max_row)
                .map(|i| {
                    table_column.assign_cell(
                        || format!("{}[{}]", table_name, i),
                        column,
                        i,
                        || CircuitValue::known(F::from_u128(i as u128)),
                    )
                })
                .fold(Ok(()), |acc, res| acc.and(res))
        },
    )?;
    Ok(())
}
