// Copyright (c) zkMove Authors

use crate::chips::execution_chip_v2::lookup_table::utils::assign_fixed_table;
use crate::table::LookupTable;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, ErrorFront as Error, TableColumn};
use types::Field;

#[derive(Copy, Clone, Debug)]
pub struct Pow2LookupTable {
    pub value_column: TableColumn,
    pub pow_lo_column: TableColumn,
    pub pow_hi_column: TableColumn,
}

impl Pow2LookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Pow2LookupTable {
            value_column: meta.lookup_table_column(),
            pow_lo_column: meta.lookup_table_column(),
            pow_hi_column: meta.lookup_table_column(),
        }
    }

    pub fn table_columns(&self) -> Vec<TableColumn> {
        vec![self.value_column, self.pow_lo_column, self.pow_hi_column]
    }

    pub fn build<F: Field>(&self) -> Vec<Vec<F>> {
        (0..256)
            .map(|value| {
                let (pow_lo, pow_hi) = if value < 128 {
                    (F::from_u128(1_u128 << value), F::from(0))
                } else {
                    (F::from(0), F::from_u128(1 << (value - 128)))
                };
                vec![F::from(value), pow_lo, pow_hi]
            })
            .collect::<Vec<_>>()
    }

    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        assign_fixed_table(
            layouter,
            self.table_columns().iter().map(|t| t.inner()).collect(),
            &self.build(),
            "pow2_table",
        )
    }
}

impl<F: Field> LookupTable<F> for Pow2LookupTable {
    fn columns(&self) -> Vec<Column<Any>> {
        self.table_columns()
            .into_iter()
            .map(|c| c.inner().into())
            .collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec!["value", "pow_lo", "pow_hi"]
            .into_iter()
            .map(ToString::to_string)
            .collect()
    }
}
