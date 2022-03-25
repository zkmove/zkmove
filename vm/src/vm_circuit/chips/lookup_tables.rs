// Copyright (c) zkMove Authors

use halo2_proofs::plonk::TableColumn;
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

#[derive(Clone)]
pub struct RWTable {
    pub gc_column: TableColumn,
    pub rw_target_column: TableColumn,
    pub rw_column: TableColumn,
    pub call_index_column: TableColumn,
    pub address_column: TableColumn,
    pub value_column: TableColumn,
}
pub const RW_LOOKUP_TABLE_WIDTH: usize = 6;

impl RWTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        RWTable {
            gc_column: meta.lookup_table_column(),
            rw_target_column: meta.lookup_table_column(),
            rw_column: meta.lookup_table_column(),
            call_index_column: meta.lookup_table_column(),
            address_column: meta.lookup_table_column(),
            value_column: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        let mut columns = Vec::new();
        columns.push(self.gc_column);
        columns.push(self.rw_target_column);
        columns.push(self.rw_column);
        columns.push(self.call_index_column);
        columns.push(self.address_column);
        columns.push(self.value_column);
        columns
    }
}
