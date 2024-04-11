// Copyright (c) zkMove Authors

use crate::chips::utilities::{Cell, Expr};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Expression, VirtualCells};
use movelang::utility::U256;
use std::hash::Hash;
use types::Field;

pub mod base_constraint_builder;
pub mod constraint_builder;
pub mod constraint_builder_v2;
pub mod dynamic_selector_half;
pub(crate) fn query_expression<F: Field, T>(
    meta: &mut ConstraintSystem<F>,
    mut f: impl FnMut(&mut VirtualCells<F>) -> T,
) -> T {
    let mut expr = None;
    meta.create_gate("Query expression", |meta| {
        expr = Some(f(meta));
        Some(0u64.expr())
    });
    expr.unwrap()
}

/// Returns 2**by as Field
pub(crate) fn pow_of_two<F: Field>(by: usize) -> F {
    F::from(2).pow([by as u64, 0, 0, 0])
}

/// Returns 2**by as Expression
pub(crate) fn pow_of_two_expr<F: Field>(by: usize) -> Expression<F> {
    Expression::Constant(pow_of_two(by))
}

/// Returns tuple consists of low and high part of U256
pub(crate) fn split_u256(value: &U256) -> (U256, U256) {
    let mask = U256::from(u128::MAX);
    let lo = *value & mask;
    let hi = (*value >> 128) & mask;
    (hi, lo)
}

/// Split a U256 value into 4 64-bit limbs stored in U256 values.
pub(crate) fn split_u256_limb64(value: &U256) -> [U256; 4] {
    let mask = U256::from(u64::MAX);
    [
        *value & mask,
        (*value >> 64) & mask,
        (*value >> 128) & mask,
        (*value >> 192) & mask,
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum CellType {
    CustomGate,
    //    Permutation,
    //    Lookup,
}

#[derive(Clone, Debug)]
pub(crate) struct CellColumn<F> {
    pub(crate) index: usize,
    pub(crate) cell_type: CellType,
    pub(crate) height: usize,
    pub(crate) expr: Expression<F>,
}

impl<F: Field> Expr<F> for CellColumn<F> {
    fn expr(&self) -> Expression<F> {
        self.expr.clone()
    }
}

#[derive(Clone, Debug)]
pub struct CellManager<F> {
    //width: usize,
    height: usize,
    cells: Vec<Cell<F>>,
    columns: Vec<CellColumn<F>>,
}

impl<F: Field> CellManager<F> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        height: usize,
        advices: &[Column<Advice>],
        height_offset: isize,
    ) -> Self {
        // Setup the columns and query the cells
        let width = advices.len();
        let mut cells = Vec::with_capacity(height * width);
        let mut columns = Vec::with_capacity(width);
        query_expression(meta, |meta| {
            for c in 0..width {
                for r in 0..height {
                    cells.push(Cell::new(
                        meta,
                        advices[c],
                        (height_offset + r as isize) as i32,
                    ));
                }
                columns.push(CellColumn {
                    index: c,
                    cell_type: CellType::CustomGate,
                    height: 0,
                    expr: cells[c * height].expression.clone(),
                });
            }
        });

        Self {
            // width,
            height,
            cells,
            columns,
        }
    }

    pub(crate) fn allocate_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        let mut cells = Vec::with_capacity(count);
        while cells.len() < count {
            let column_idx = self.next_column(cell_type);
            let column = &mut self.columns[column_idx];
            cells.push(self.cells[column_idx * self.height + column.height].clone());
            column.height += 1;
        }
        cells
    }

    pub(crate) fn alloc_cell(&mut self, cell_type: CellType) -> Cell<F> {
        self.allocate_cells(cell_type, 1)[0].clone()
    }

    fn next_column(&self, cell_type: CellType) -> usize {
        let mut best_index: Option<usize> = None;
        let mut best_height = self.height;
        for column in self.columns.iter() {
            if column.cell_type == cell_type && column.height < best_height {
                best_index = Some(column.index);
                best_height = column.height;
            }
        }

        match best_index {
            Some(index) => index,
            // If we reach this case, it means that all the columns of cell_type have assignments
            // taking self.height rows, so there's no more space.
            None => panic!("not enough cells for query: {:?}", cell_type),
        }
    }

    pub(crate) fn get_height(&self) -> usize {
        self.columns
            .iter()
            .map(|column| column.height)
            .max()
            .unwrap()
    }
    /*
    /// Returns a map of CellType -> (width, height, num_cells)
    pub(crate) fn get_stats(&self) -> BTreeMap<CellType, (usize, usize, usize)> {
        let mut data = BTreeMap::new();
        for column in self.columns.iter() {
            let (mut count, mut height, mut num_cells) =
                data.get(&column.cell_type).unwrap_or(&(0, 0, 0));
            count += 1;
            height = height.max(column.height);
            num_cells += column.height;
            data.insert(column.cell_type, (count, height, num_cells));
        }
        data
    }

    pub(crate) fn columns(&self) -> &[CellColumn<F>] {
        &self.columns
    }
    */
}
