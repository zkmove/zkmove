use halo2_proofs::plonk::{Expression, TableColumn};
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

#[derive(Clone, Debug)]
pub struct CallLookupTable {
    pub type_column: TableColumn,
    pub module_index_column: TableColumn,
    pub function_index_column: TableColumn,
    pub pc_column: TableColumn,
    pub callee_module_index_column: TableColumn,
    pub callee_function_index_column: TableColumn,
    pub next_pc_column: TableColumn,
}

pub const CALL_LOOKUP_TABLE_WIDTH: usize = 7;

impl CallLookupTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        CallLookupTable {
            type_column: meta.lookup_table_column(),
            module_index_column: meta.lookup_table_column(),
            function_index_column: meta.lookup_table_column(),
            pc_column: meta.lookup_table_column(),
            callee_module_index_column: meta.lookup_table_column(),
            callee_function_index_column: meta.lookup_table_column(),
            next_pc_column: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![
            self.type_column,
            self.module_index_column,
            self.function_index_column,
            self.pc_column,
            self.callee_module_index_column,
            self.callee_function_index_column,
            self.next_pc_column,
        ]
    }
}

pub struct CallLookup<F: FieldExt> {
    pub type_: Expression<F>,
    pub module_index: Expression<F>,
    pub function_index: Expression<F>,
    pub pc: Expression<F>,
    pub next_module_index: Expression<F>,
    pub next_function_index: Expression<F>,
    pub next_pc: Expression<F>,
}
