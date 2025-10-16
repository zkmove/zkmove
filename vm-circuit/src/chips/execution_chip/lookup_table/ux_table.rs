// Copyright (c) zkMove Authors
// All right reserved to zkevm-circuits.
use super::*;
use crate::chips::execution_chip::lookup_table::utils::assign_fixed_table;
use crate::table::LookupTable;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{
    Any, Column, ConstraintSystem, ErrorFront as Error, Fixed, VirtualCells,
};
use halo2_proofs::poly::Rotation;

/// Lookup table for max n bits range check
#[derive(Clone, Copy, Debug)]
pub struct UXTable<const N_BITS: usize> {
    col: Column<Fixed>,
}

impl<const N_BITS: usize> UXTable<N_BITS> {
    /// Construct the UXTable.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            col: meta.fixed_column(),
        }
    }

    pub fn columns(&self) -> Vec<Column<Fixed>> {
        vec![self.col]
    }

    pub(crate) fn build<F: Field>(&self) -> impl Iterator<Item = [F; 1]> {
        (0..(1 << N_BITS)).map(move |value| [F::from(value as u64)])
    }

    /// Load the `UXTable` for range check
    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        // Collect the iterator into Vec<Vec<F>>
        let values: Vec<Vec<F>> = self.build().map(|row| row.to_vec()).collect();

        // Assign the values to the fixed table
        assign_fixed_table(
            layouter,
            self.columns(),
            &values,
            &format!("UX_Table u{}", N_BITS),
        )
    }
}

impl<F: Field, const N_BITS: usize> LookupTable<F> for UXTable<N_BITS> {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![self.col.into()]
    }

    fn annotations(&self) -> Vec<String> {
        vec![format!("u{}_col", N_BITS)]
    }

    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![meta.query_fixed(self.col, Rotation::cur())]
    }
}
