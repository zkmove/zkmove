// Copyright (c) zkMove Authors

use crate::table::LookupTable;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, TableColumn};
use types::Field;

#[derive(Clone, Debug)]
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
}

impl<F: Field> LookupTable<F> for Pow2LookupTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![self.value_column, self.pow_lo_column, self.pow_hi_column]
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
