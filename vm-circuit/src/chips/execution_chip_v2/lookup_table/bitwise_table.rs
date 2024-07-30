// Copyright (c) zkMove Authors

use crate::table::LookupTable;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, TableColumn};
use types::Field;

#[derive(Clone, Debug)]
pub struct BitwiseLookupTable {
    pub opcode_column: TableColumn,
    pub value_1_column: TableColumn,
    pub value_2_column: TableColumn,
    pub result_column: TableColumn,
}

impl BitwiseLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        BitwiseLookupTable {
            opcode_column: meta.lookup_table_column(),
            value_1_column: meta.lookup_table_column(),
            value_2_column: meta.lookup_table_column(),
            result_column: meta.lookup_table_column(),
        }
    }
}

impl<F: Field> LookupTable<F> for BitwiseLookupTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.opcode_column,
            self.value_1_column,
            self.value_2_column,
            self.result_column,
        ]
        .into_iter()
        .map(|c| c.inner().into())
        .collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec!["opcode", "value_1", "value_2", "result"]
            .into_iter()
            .map(ToString::to_string)
            .collect()
    }
}
