// Copyright (c) zkMove Authors

use crate::table::LookupTable;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, TableColumn};
use types::Field;

#[derive(Clone, Debug)]
pub struct FunctionLookupTable {
    pub module_index_column: TableColumn,
    pub function_index_column: TableColumn,
    pub num_arg_column: TableColumn,
}

impl FunctionLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        FunctionLookupTable {
            module_index_column: meta.lookup_table_column(),
            function_index_column: meta.lookup_table_column(),
            num_arg_column: meta.lookup_table_column(),
        }
    }
}

impl<F: Field> LookupTable<F> for FunctionLookupTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.module_index_column,
            self.function_index_column,
            self.num_arg_column,
        ]
        .into_iter()
        .map(|c| c.inner().into())
        .collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec!["module_index", "function_index", "num_arg"]
            .into_iter()
            .map(ToString::to_string)
            .collect()
    }
}
