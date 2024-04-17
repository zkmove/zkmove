use crate::table::LookupTable;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, TableColumn};
use types::Field;
#[derive(Copy, Clone, Debug)]
pub struct BytecodeLookupTable {
    pub module_index_column: TableColumn,
    pub function_index_column: TableColumn,
    pub pc_column: TableColumn,
    pub opcode_column: TableColumn,
    pub aux0_column: TableColumn,
    pub aux1_column: TableColumn,
}

impl BytecodeLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            module_index_column: meta.lookup_table_column(),
            function_index_column: meta.lookup_table_column(),
            pc_column: meta.lookup_table_column(),
            opcode_column: meta.lookup_table_column(),
            aux0_column: meta.lookup_table_column(),
            aux1_column: meta.lookup_table_column(),
        }
    }
}

impl<F: Field> LookupTable<F> for BytecodeLookupTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.module_index_column,
            self.function_index_column,
            self.pc_column,
            self.opcode_column,
            self.aux0_column,
            self.aux1_column,
        ]
        .into_iter()
        .map(|c| c.inner().into())
        .collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            "module_index",
            "function_index",
            "pc",
            "opcode",
            "aux0",
            "aux1",
        ]
        .into_iter()
        .map(ToString::to_string)
        .collect()
    }
}
